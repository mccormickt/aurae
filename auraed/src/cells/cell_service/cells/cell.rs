/* -------------------------------------------------------------------------- *\
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 * -------------------------------------------------------------------------- *
 * Copyright 2022 - 2024, the aurae contributors                              *
 * SPDX-License-Identifier: Apache-2.0                                        *
\* -------------------------------------------------------------------------- */

use super::{
    CellName, CellSpec, Cells, CellsCache, CellsError, Result, cgroups::Cgroup,
    nested_auraed::NestedAuraed,
};
use crate::init::network::Network;
use crate::init::network::endpoint::NetworkConfig;
use crate::init::network::ipam::Allocation;
use client::AuraeSocket;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// The maximum time that `Cell::allocate` waits for the Unix socket of
/// the nested auraed. The child first runs `init_endpoint`, which has its
/// own poll timeout of 5 s, and then creates the socket. A limit of 10 s
/// gives a sufficient margin and does not block the caller.
const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(10);

// TODO https://github.com/aurae-runtime/aurae/issues/199 &&
//      aurae.io/signals, which is more accurate
// TODO nested auraed should proxy (bus) POSIX signals to child executables

// We should not be able to change a cell after it has been created.
// You must free the cell and create a new one if you want to change anything about the cell.
// In order to facilitate that immutability:
// NEVER MAKE THE FIELDS PUB (OF ANY KIND)
#[derive(Debug)]
pub struct Cell {
    cell_name: CellName,
    spec: CellSpec,
    state: CellState,
}

#[derive(Debug)]
struct CellNetwork {
    network: Network,
    allocation: Allocation,
}

#[derive(Debug)]
struct PendingCleanup {
    nested_auraed: Option<NestedAuraed>,
    cgroup: Option<Cgroup>,
    cell_network: Option<CellNetwork>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum CellState {
    Unallocated,
    CleanupPending(PendingCleanup),
    Allocated {
        cgroup: Cgroup,
        nested_auraed: NestedAuraed,
        children: Cells,
        /// `Some` only if `iso_ctl.isolate_network` is set on this cell.
        /// `free()` then releases the IPAM slot and deletes the host-side
        /// primary.
        cell_network: Option<CellNetwork>,
    },
    Freed,
}

impl Cell {
    pub fn new(cell_name: CellName, cell_spec: CellSpec) -> Self {
        Self { cell_name, spec: cell_spec, state: CellState::Unallocated }
    }

    pub(super) fn can_allocate(&self) -> bool {
        matches!(self.state, CellState::Unallocated | CellState::Freed)
    }

    /// The key of the IPAM slot of a cell. The allocate, free, and kill
    /// paths must calculate the same key, so that each path uses the key of
    /// the reservation. The function is an associated function and not a
    /// method. A teardown path can call it while it holds a mutable
    /// borrow of `self.state`.
    fn ipam_key(cell_name: &CellName) -> String {
        format!("cell:{cell_name}")
    }

    /// Signal the nested auraed and delete the cgroup. Shared by
    /// `free` (graceful `shutdown`) and `kill` (forceful `kill`).
    /// Callers should reclaim the network and IPAM state before
    /// propagating errors.
    fn teardown_process_and_cgroup(
        cell_name: &CellName,
        cgroup: &Cgroup,
        signal_result: io::Result<std::process::ExitStatus>,
    ) -> Result<()> {
        let _exit_status = signal_result.map_err(|e| {
            CellsError::FailedToKillCellChildren {
                cell_name: cell_name.clone(),
                source: e,
            }
        })?;

        cgroup.delete().map_err(|e| CellsError::FailedToFreeCell {
            cell_name: cell_name.clone(),
            source: e,
        })?;
        Ok(())
    }

    /// Remove the cell network and release its address.
    ///
    /// The allocation stays in the state until both operations succeed.
    async fn release_network(
        cell_name: &CellName,
        cell_network: &mut Option<CellNetwork>,
    ) -> Result<()> {
        let Some(resource) = cell_network.as_ref() else {
            return Ok(());
        };

        resource.network.destroy_cell_interface(cell_name).await.map_err(
            |source| CellsError::NetworkSetupFailed {
                cell_name: cell_name.clone(),
                source: Box::new(source),
            },
        )?;

        let key = Self::ipam_key(cell_name);
        let _released =
            resource.network.ipam().release(&key).map_err(|source| {
                CellsError::IpamFailed { cell_name: cell_name.clone(), source }
            })?;
        *cell_network = None;
        Ok(())
    }

    async fn retry_pending_cleanup(&mut self) -> Result<()> {
        let CellState::CleanupPending(cleanup) = &mut self.state else {
            return Ok(());
        };

        let process_result =
            if let Some(auraed) = cleanup.nested_auraed.as_mut() {
                auraed.kill().await.map(|_status| ()).map_err(|source| {
                    CellsError::FailedToKillCellChildren {
                        cell_name: self.cell_name.clone(),
                        source,
                    }
                })
            } else {
                Ok(())
            };
        if process_result.is_ok() {
            cleanup.nested_auraed = None;
        }

        let cgroup_result = if let Some(cell_cgroup) = cleanup.cgroup.as_ref() {
            cell_cgroup.delete().map_err(|source| {
                CellsError::FailedToFreeCell {
                    cell_name: self.cell_name.clone(),
                    source,
                }
            })
        } else {
            Ok(())
        };
        if cgroup_result.is_ok() {
            cleanup.cgroup = None;
        }

        let network_result =
            Self::release_network(&self.cell_name, &mut cleanup.cell_network)
                .await;

        process_result?;
        cgroup_result?;
        network_result?;
        self.state = CellState::Freed;
        Ok(())
    }

    async fn rollback_allocation(&mut self, cleanup: PendingCleanup) {
        self.state = CellState::CleanupPending(cleanup);
        if let Err(error) = self.retry_pending_cleanup().await {
            warn!("Cell {}: rollback failed: {error}", self.cell_name);
        }
    }

    /// Allocate the cell. The function reserves an IPAM slot if
    /// `isolate_network` is true. It starts the nested auraed, which owns
    /// the network namespace of the cell. It creates the cgroup and puts the nested
    /// auraed into it. Then it creates the host-side primary and moves the
    /// peer into the network namespace.
    ///
    /// On an error the function releases the resources again. It stops the
    /// nested auraed, deletes the cgroup, and releases the IPAM slot.
    // Here is where we define the "default" cgroup parameters for Aurae cells
    pub(crate) async fn allocate(
        &mut self,
        host_network: Option<Network>,
    ) -> Result<()> {
        let CellState::Unallocated = &self.state else {
            return Ok(());
        };

        let key = Self::ipam_key(&self.cell_name);

        // Step 1: reserve an IPAM slot if the cell needs an isolated
        // network. The allocator is part of `Network`. A `Network`
        // handle gives an allocator.
        let cell_network = if self.spec.iso_ctl.isolate_network {
            let Some(network) = host_network.as_ref() else {
                return Err(CellsError::NetworkUnavailable {
                    cell_name: self.cell_name.clone(),
                });
            };
            let allocation = network.ipam().allocate(&key).map_err(|e| {
                CellsError::IpamFailed {
                    cell_name: self.cell_name.clone(),
                    source: e,
                }
            })?;
            Some(CellNetwork { network: network.clone(), allocation })
        } else {
            None
        };

        // Step 2: reserve the unique primary and peer names before the
        // start of the child. The peer name must be in the environment of
        // the child, and the environment is fixed at the exec. Step 5
        // creates the links.
        let interface_names = cell_network
            .as_ref()
            .map(|cell_network| cell_network.network.reserve_interface_names());

        // Step 3: build the CLI arguments. The child auraed parses them at
        // its start and configures its endpoint. It renames the peer to
        // `eth0` and adds the addresses and routes.
        let net_config = cell_network
            .as_ref()
            .zip(interface_names.as_ref())
            .map(|(cell_network, (_, peer))| {
                NetworkConfig::from_allocation(
                    &cell_network.allocation,
                    peer.clone(),
                )
            });

        // Step 4: spawn the nested auraed.
        let name = self.cell_name.leaf().to_string();
        let auraed = match NestedAuraed::new(
            name,
            self.spec.iso_ctl.clone(),
            net_config,
        ) {
            Ok(a) => a,
            Err(e) => {
                self.rollback_allocation(PendingCleanup {
                    nested_auraed: None,
                    cgroup: None,
                    cell_network,
                })
                .await;
                return Err(CellsError::FailedToAllocateCell {
                    cell_name: self.cell_name.clone(),
                    source: e,
                });
            }
        };

        let pid = auraed.pid();

        // Step 5: cgroup setup.
        let cgroup = match Cgroup::new(
            self.cell_name.clone(),
            self.spec.cgroup_spec.clone(),
            pid,
        ) {
            Ok(cgroup) => cgroup,
            Err(e) => {
                self.rollback_allocation(PendingCleanup {
                    nested_auraed: Some(auraed),
                    cgroup: None,
                    cell_network,
                })
                .await;
                return Err(CellsError::AbortedAllocateCell {
                    cell_name: self.cell_name.clone(),
                    source: e,
                });
            }
        };

        if let Err(e) = cgroup.add_task(pid) {
            self.rollback_allocation(PendingCleanup {
                nested_auraed: Some(auraed),
                cgroup: Some(cgroup),
                cell_network,
            })
            .await;
            return Err(CellsError::AbortedAllocateCell {
                cell_name: self.cell_name.clone(),
                source: e,
            });
        }

        info!("Attach nested Auraed pid {} to cgroup {}", pid, self.cell_name);

        // Step 6: create the host-side primary and move the peer into the
        // network namespace of the cell. An error here rolls back all steps.
        if let (Some(cell_network_ref), Some((primary, peer))) =
            (cell_network.as_ref(), interface_names.as_ref())
        {
            let netns_path = format!("/proc/{}/ns/net", pid.as_raw());
            let netns_file = match File::open(&netns_path) {
                Ok(f) => f,
                Err(e) => {
                    self.rollback_allocation(PendingCleanup {
                        nested_auraed: Some(auraed),
                        cgroup: Some(cgroup),
                        cell_network,
                    })
                    .await;
                    return Err(CellsError::FailedToAllocateCell {
                        cell_name: self.cell_name.clone(),
                        source: e,
                    });
                }
            };
            if let Err(e) = cell_network_ref
                .network
                .create_cell_interface(
                    &self.cell_name,
                    &cell_network_ref.allocation,
                    netns_file.as_fd(),
                    primary,
                    peer,
                )
                .await
            {
                self.rollback_allocation(PendingCleanup {
                    nested_auraed: Some(auraed),
                    cgroup: Some(cgroup),
                    cell_network,
                })
                .await;
                return Err(CellsError::NetworkSetupFailed {
                    cell_name: self.cell_name.clone(),
                    source: Box::new(e),
                });
            }
        }

        // Step 7: wait for the end of the startup of the nested auraed.
        // Its Unix socket appears only after `CellSystemRuntime::init`
        // completes, which includes `init_endpoint` if the CLI flags are
        // set. Thus the socket shows that the cell is reachable. If the
        // socket does not appear before the timeout, the child probably
        // failed in `init_endpoint`. Stop the child and roll back, so that
        // the caller sees the failure here and not at the next gRPC
        // call.
        if let Err(e) =
            wait_for_client_socket(&auraed.client_socket, CHILD_READY_TIMEOUT)
                .await
        {
            self.rollback_allocation(PendingCleanup {
                nested_auraed: Some(auraed),
                cgroup: Some(cgroup),
                cell_network,
            })
            .await;
            return Err(CellsError::FailedToAllocateCell {
                cell_name: self.cell_name.clone(),
                source: e,
            });
        }

        self.state = CellState::Allocated {
            cgroup,
            nested_auraed: auraed,
            children: Cells::new(self.cell_name.clone(), host_network),
            cell_network,
        };

        Ok(())
    }

    /// Stop a cell and release all resources.
    ///
    /// The state stays allocated if a cleanup step fails.
    pub(crate) async fn free(&mut self) -> Result<()> {
        if matches!(self.state, CellState::CleanupPending(_)) {
            return self.retry_pending_cleanup().await;
        }

        if let CellState::Allocated {
            cgroup,
            nested_auraed,
            children,
            cell_network,
        } = &mut self.state
        {
            let children_teardown = children.broadcast_free().await;

            let signal_result = nested_auraed.shutdown().await;
            let teardown = Self::teardown_process_and_cgroup(
                &self.cell_name,
                cgroup,
                signal_result,
            );
            let network_teardown =
                Self::release_network(&self.cell_name, cell_network).await;
            teardown?;
            network_teardown?;
            children_teardown?;
        }

        self.state = CellState::Freed;
        Ok(())
    }

    /// Kill a cell and release all resources.
    pub(crate) async fn kill(&mut self) -> Result<()> {
        if matches!(self.state, CellState::CleanupPending(_)) {
            return self.retry_pending_cleanup().await;
        }

        if let CellState::Allocated {
            cgroup,
            nested_auraed,
            children,
            cell_network,
        } = &mut self.state
        {
            let children_teardown = children.broadcast_kill().await;

            let signal_result = nested_auraed.kill().await;
            let teardown = Self::teardown_process_and_cgroup(
                &self.cell_name,
                cgroup,
                signal_result,
            );
            let network_teardown =
                Self::release_network(&self.cell_name, cell_network).await;
            teardown?;
            network_teardown?;
            children_teardown?;
        }

        self.state = CellState::Freed;
        Ok(())
    }

    /// Performs bounded synchronous cleanup during `Drop`.
    ///
    /// This path keeps the network allocation. The daemon cannot confirm
    /// an asynchronous link deletion from `Drop`.
    pub(super) fn kill_for_drop(&mut self) {
        let deadline = Instant::now() + super::nested_auraed::REAP_TIMEOUT;
        self.signal_kill_for_drop();
        self.reap_kill_for_drop(deadline);
    }

    pub(super) fn signal_kill_for_drop(&mut self) {
        match &mut self.state {
            CellState::CleanupPending(cleanup) => {
                if let Some(auraed) = cleanup.nested_auraed.as_mut() {
                    let _best_effort = auraed.signal_kill_for_drop();
                }
            }
            CellState::Allocated { nested_auraed, children, .. } => {
                children.signal_kill_for_drop();
                let _best_effort = nested_auraed.signal_kill_for_drop();
            }
            CellState::Unallocated | CellState::Freed => {}
        }
    }

    pub(super) fn reap_kill_for_drop(&mut self, deadline: Instant) {
        if let CellState::CleanupPending(cleanup) = &mut self.state {
            if let Some(auraed) = cleanup.nested_auraed.as_mut() {
                let _best_effort = auraed.reap_for_drop(deadline);
            }
            if let Some(cell_cgroup) = cleanup.cgroup.as_ref() {
                let _best_effort = cell_cgroup.delete();
            }
            if cleanup.cell_network.is_some() {
                warn!(
                    "Cell {}: retained the network allocation during Drop",
                    self.cell_name
                );
            }
            return;
        }

        let CellState::Allocated {
            cgroup,
            nested_auraed,
            children,
            cell_network,
            ..
        } = &mut self.state
        else {
            return;
        };

        children.reap_kill_for_drop(deadline);
        let signal_result = nested_auraed.reap_for_drop(deadline);
        let _best_effort = Self::teardown_process_and_cgroup(
            &self.cell_name,
            cgroup,
            signal_result,
        );
        if cell_network.is_some() {
            warn!(
                "Cell {}: retained the network allocation during Drop",
                self.cell_name
            );
        }
    }

    pub fn client_socket(&self) -> Result<AuraeSocket> {
        let CellState::Allocated { nested_auraed, .. } = &self.state else {
            return Err(CellsError::CellNotAllocated {
                cell_name: self.cell_name.clone(),
            });
        };

        Ok(nested_auraed.client_socket.clone())
    }

    /// Returns the [CellName] of the [Cell]
    pub fn name(&self) -> &CellName {
        &self.cell_name
    }

    pub fn spec(&self) -> &CellSpec {
        &self.spec
    }

    /// Returns [None] if the [Cell] is not allocated.
    pub fn v2(&self) -> Option<bool> {
        let CellState::Allocated { cgroup, .. } = &self.state else {
            return None;
        };

        Some(cgroup.v2())
    }
}

/// Wait for the Unix socket file of the nested auraed. The child creates
/// this socket as the last step of `CellSystemRuntime::init`. Thus the
/// socket shows the end of the startup of the child. The function polls
/// the file system, because a local `stat` call takes microseconds. It
/// does not connect, because a connection makes the daemon do a TLS
/// handshake that this function does not need.
///
/// An `AuraeSocket::Addr` is always ready. That variant is for TCP, where
/// the address is immediately available and the connect call blocks.
async fn wait_for_client_socket(
    socket: &AuraeSocket,
    timeout: Duration,
) -> io::Result<()> {
    let path = match socket {
        AuraeSocket::Path(p) => p.clone(),
        AuraeSocket::Addr(_) => return Ok(()),
    };
    let start = Instant::now();
    loop {
        if path.exists() {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "nested auraed socket {} did not appear within {}s",
                    path.display(),
                    timeout.as_secs()
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl CellsCache for Cell {
    async fn allocate(
        &mut self,
        cell_name: CellName,
        cell_spec: CellSpec,
    ) -> Result<&Cell> {
        let CellState::Allocated { children, .. } = &mut self.state else {
            return Err(CellsError::CellNotAllocated {
                cell_name: self.cell_name.clone(),
            });
        };

        children.allocate(cell_name, cell_spec).await
    }

    async fn free(&mut self, cell_name: &CellName) -> Result<()> {
        let CellState::Allocated { children, .. } = &mut self.state else {
            return Err(CellsError::CellNotAllocated {
                cell_name: self.cell_name.clone(),
            });
        };

        children.free(cell_name).await
    }

    fn get<F, R>(&mut self, cell_name: &CellName, f: F) -> Result<R>
    where
        F: Fn(&Cell) -> Result<R>,
    {
        let CellState::Allocated { children, .. } = &mut self.state else {
            return Err(CellsError::CellNotAllocated {
                cell_name: self.cell_name.clone(),
            });
        };

        children.get(cell_name, f)
    }

    fn get_all<F, R>(&self, f: F) -> Result<Vec<Result<R>>>
    where
        F: Fn(&Cell) -> Result<R>,
    {
        let CellState::Allocated { children, .. } = &self.state else {
            return Err(CellsError::CellNotAllocated {
                cell_name: self.cell_name.clone(),
            });
        };

        children.get_all(f)
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        self.kill_for_drop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::network::ipam::IpamConfig;
    use crate::{AURAED_RUNTIME, AuraedRuntime};
    use test_helpers::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_cant_unfree() {
        skip_if_not_root!("test_cant_unfree");
        // Docker's seccomp security profile (https://docs.docker.com/engine/security/seccomp/) blocks clone
        skip_if_seccomp!("test_cant_unfree");

        let _ = AURAED_RUNTIME.set(AuraedRuntime::default());

        let cell_name = CellName::random_for_tests();
        let mut cell = Cell::new(cell_name, CellSpec::new_for_tests());
        assert!(matches!(cell.state, CellState::Unallocated));

        cell.allocate(None).await.expect("failed to allocate");
        assert!(matches!(cell.state, CellState::Allocated { .. }));

        cell.free().await.expect("failed to free");
        assert!(matches!(cell.state, CellState::Freed));

        // Calling allocate again should do nothing
        cell.allocate(None).await.expect("failed to allocate 2");
        assert!(matches!(cell.state, CellState::Freed));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn free_retries_pending_network_cleanup() {
        let cell_name = CellName::random_for_tests();
        let network = Network::connect(IpamConfig::default()).expect("network");
        let key = Cell::ipam_key(&cell_name);
        let allocation = network.ipam().allocate(&key).expect("allocation");
        let mut cell = Cell::new(cell_name, CellSpec::new_for_tests());
        cell.state = CellState::CleanupPending(PendingCleanup {
            nested_auraed: None,
            cgroup: None,
            cell_network: Some(CellNetwork {
                network: network.clone(),
                allocation,
            }),
        });

        cell.free().await.expect("cleanup");

        assert!(matches!(cell.state, CellState::Freed));
        let _reused = network.ipam().allocate(&key).expect("reused allocation");
    }
}
