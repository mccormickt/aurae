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
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Maximum time `Cell::allocate` waits for the nested auraed's unix
/// socket to appear after we've set up host-side networking. The child
/// runs `init_endpoint` (which has its own 5s eth0-poll timeout) then
/// creates the socket, so 10s gives a comfortable margin without
/// hanging callers indefinitely.
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

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum CellState {
    Unallocated,
    Allocated {
        cgroup: Cgroup,
        nested_auraed: NestedAuraed,
        children: Cells,
        /// `Some` iff `iso_ctl.isolate_network` was set on this cell, in
        /// which case `free()` releases the IPAM slot and tears down the
        /// host-side interface primary.
        ipam_allocation: Option<Allocation>,
        /// Stored so `free()` can talk to the host's `Network` (which
        /// owns the IPAM allocator) without requiring the caller to
        /// thread it back in.
        network: Option<Arc<Network>>,
    },
    Freed,
}

impl Cell {
    pub fn new(cell_name: CellName, cell_spec: CellSpec) -> Self {
        Self { cell_name, spec: cell_spec, state: CellState::Unallocated }
    }

    /// Allocates the cell: reserves an IPAM slot if `isolate_network=true`,
    /// spawns the nested auraed (which owns the cell's netns), creates the
    /// cgroup and attaches the nested auraed to it, then sets up the
    /// host-side interface primary and moves the peer into the netns.
    ///
    /// On error, rolls back resources allocated so far (kill the nested
    /// auraed, delete the cgroup, release the IPAM slot).
    // Here is where we define the "default" cgroup parameters for Aurae cells
    pub(crate) async fn allocate(
        &mut self,
        network: Option<Arc<Network>>,
    ) -> Result<()> {
        let CellState::Unallocated = &self.state else {
            return Ok(());
        };

        let key = format!("cell:{}", self.cell_name);

        // Step 1: reserve an IPAM slot if the cell wants network isolation.
        // The IPAM allocator lives inside `Network`, so a present `network`
        // implies an available allocator.
        let allocation = if self.spec.iso_ctl.isolate_network {
            let Some(net) = network.as_ref() else {
                return Err(CellsError::NetworkUnavailable {
                    cell_name: self.cell_name.clone(),
                });
            };
            let allocation = net.ipam.allocate(&key).map_err(|e| {
                CellsError::IpamFailed {
                    cell_name: self.cell_name.clone(),
                    source: e,
                }
            })?;
            Some(allocation)
        } else {
            None
        };

        // Closure to release the IPAM slot from any rollback path. Pulls
        // `network` and `key` by reference so each rollback site is a
        // single line.
        let release_ipam = |net: &Option<Arc<Network>>| {
            if allocation.is_some()
                && let Some(net) = net.as_ref()
                && let Err(e) = net.ipam.release(&key)
            {
                warn!(
                    "Rollback: failed to release IPAM for {}: {e}",
                    self.cell_name
                );
            }
        };

        // Step 2: reserve unique interface primary/peer names BEFORE spawning
        // the child. The peer name has to be in the env var passed to
        // exec; we can't generate it later because env is fixed at exec
        // time. We pick the names now and create the actual links in
        // step 5.
        let interface_names = match (&allocation, &network) {
            (Some(_), Some(net)) => Some(net.reserve_interface_names()),
            _ => None,
        };

        // Step 3: build CLI args the child auraed will parse at startup
        // to self-configure its endpoint (rename peer→eth0, add addrs,
        // routes).
        let net_config = match (allocation.as_ref(), interface_names.as_ref()) {
            (Some(alloc), Some((_, peer))) => {
                Some(NetworkConfig::from_allocation(alloc, peer.clone()))
            }
            _ => None,
        };

        // Step 4: spawn the nested auraed.
        let name = self.cell_name.leaf().to_string();
        let mut auraed = match NestedAuraed::new(
            name,
            self.spec.iso_ctl.clone(),
            net_config,
        ) {
            Ok(a) => a,
            Err(e) => {
                release_ipam(&network);
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
                let _best_effort = auraed.kill();
                release_ipam(&network);
                return Err(CellsError::AbortedAllocateCell {
                    cell_name: self.cell_name.clone(),
                    source: e,
                });
            }
        };

        if let Err(e) = cgroup.add_task(pid) {
            let _best_effort = auraed.kill();
            let _best_effort = cgroup.delete();
            release_ipam(&network);
            return Err(CellsError::AbortedAllocateCell {
                cell_name: self.cell_name.clone(),
                source: e,
            });
        }

        info!("Attach nested Auraed pid {} to cgroup {}", pid, self.cell_name);

        // Step 6: create the host-side interface primary and move the peer
        // into the cell's netns. Errors here roll back everything.
        if let (Some(allocation), Some(net), Some((primary, peer))) =
            (&allocation, &network, &interface_names)
        {
            let netns_path = format!("/proc/{}/ns/net", pid.as_raw());
            let netns_file = match File::open(&netns_path) {
                Ok(f) => f,
                Err(e) => {
                    let _best_effort = auraed.kill();
                    let _best_effort = cgroup.delete();
                    release_ipam(&network);
                    return Err(CellsError::FailedToAllocateCell {
                        cell_name: self.cell_name.clone(),
                        source: e,
                    });
                }
            };
            if let Err(e) = net
                .create_cell_interface(
                    &self.cell_name,
                    allocation,
                    netns_file.as_raw_fd(),
                    primary,
                    peer,
                )
                .await
            {
                let _best_effort = auraed.kill();
                let _best_effort = cgroup.delete();
                release_ipam(&network);
                return Err(CellsError::NetworkSetupFailed {
                    cell_name: self.cell_name.clone(),
                    source: Box::new(e),
                });
            }
        }

        // Step 7: wait for the nested auraed to finish its own startup.
        // Its unix socket appears only after CellSystemRuntime::init
        // completes (which includes init_endpoint when CLI flags are
        // set), so socket existence proves the cell is reachable. If the
        // socket doesn't appear within the timeout the child probably
        // failed in init_endpoint; kill it and roll back so the caller
        // sees the failure here instead of on the next gRPC call.
        if let Err(e) =
            wait_for_client_socket(&auraed.client_socket, CHILD_READY_TIMEOUT)
                .await
        {
            let _best_effort = auraed.kill();
            let _best_effort = cgroup.delete();
            if let Some(net) = network.as_ref() {
                let _ = net.destroy_cell_interface(&self.cell_name).await;
            }
            release_ipam(&network);
            return Err(CellsError::FailedToAllocateCell {
                cell_name: self.cell_name.clone(),
                source: e,
            });
        }

        self.state = CellState::Allocated {
            cgroup,
            nested_auraed: auraed,
            children: Cells::new(self.cell_name.clone(), network.clone()),
            ipam_allocation: allocation,
            network,
        };

        Ok(())
    }

    /// Broadcasts a graceful shutdown signal to all [NestedAuraed] and
    /// deletes the underlying cgroup and all descendants. Releases the
    /// IPAM slot and tears down the host-side interface primary if this cell
    /// had `isolate_network=true`.
    ///
    /// The [Cell::state] will be set to [CellState::Freed] regardless of
    /// it's state prior to this call.
    ///
    /// A [Cell] should never be reused once in the [CellState::Freed] state.
    #[async_recursion::async_recursion]
    pub(crate) async fn free(&mut self) -> Result<()> {
        if let CellState::Allocated {
            cgroup,
            nested_auraed,
            children,
            ipam_allocation,
            network,
        } = &mut self.state
        {
            children.broadcast_free().await;

            // Shut down processes and delete the cgroup, but don't let
            // either failure skip the network/IPAM cleanup below — a
            // half-freed cell must not leak its host-side interface,
            // guard state, or address slot.
            let teardown: Result<()> = (|| {
                let _exit_status = nested_auraed.shutdown().map_err(|e| {
                    CellsError::FailedToKillCellChildren {
                        cell_name: self.cell_name.clone(),
                        source: e,
                    }
                })?;

                cgroup.delete().map_err(|e| CellsError::FailedToFreeCell {
                    cell_name: self.cell_name.clone(),
                    source: e,
                })?;
                Ok(())
            })();

            if ipam_allocation.is_some()
                && let Some(net) = network.as_ref()
            {
                if let Err(e) =
                    net.destroy_cell_interface(&self.cell_name).await
                {
                    warn!(
                        "Cell {}: failed to destroy host interface primary: \
                         {e}. Host-side interface may leak.",
                        self.cell_name
                    );
                }
                let key = format!("cell:{}", self.cell_name);
                if let Err(e) = net.ipam.release(&key) {
                    warn!(
                        "Cell {}: failed to release IPAM slot: {e}",
                        self.cell_name
                    );
                }
            }

            // Propagate the first teardown failure now that the network
            // state is reclaimed. The state stays Allocated so a retry
            // (or Drop's kill) can still reach the processes; the
            // already-reclaimed network cleanup paths are no-ops then.
            teardown?;
        }

        self.state = CellState::Freed;
        Ok(())
    }

    /// Sends a [SIGKILL] to the [NestedAuraed], deletes the underlying
    /// cgroup, and synchronously reclaims the cell's host-side network
    /// state: guard link + BPF map entries (via
    /// `Network::reclaim_cell_interface_sync`) and the IPAM slot. The
    /// netlink deletion of the primary itself is async-only, so it is
    /// spawned onto the runtime when one exists — the primary normally
    /// dies with the cell's netns anyway, and a recycled ifindex fails
    /// closed in the guard regardless.
    pub fn kill(&mut self) -> Result<()> {
        if let CellState::Allocated {
            cgroup,
            nested_auraed,
            children,
            ipam_allocation,
            network,
        } = &mut self.state
        {
            children.broadcast_kill();

            // As in free(): a kill/cgroup failure must not skip the
            // network/IPAM reclamation below.
            let teardown: Result<()> = (|| {
                let _exit_status = nested_auraed.kill().map_err(|e| {
                    CellsError::FailedToKillCellChildren {
                        cell_name: self.cell_name.clone(),
                        source: e,
                    }
                })?;

                cgroup.delete().map_err(|e| CellsError::FailedToFreeCell {
                    cell_name: self.cell_name.clone(),
                    source: e,
                })?;
                Ok(())
            })();

            if ipam_allocation.is_some()
                && let Some(net) = network.as_ref()
            {
                let key = format!("cell:{}", self.cell_name);
                match (
                    net.reclaim_cell_interface_sync(&self.cell_name),
                    tokio::runtime::Handle::try_current(),
                ) {
                    (Some(primary), Ok(handle)) => {
                        // Delete the primary BEFORE releasing the IPAM
                        // slot: the reuse stack is LIFO, so an immediate
                        // re-allocation could otherwise get this cell's
                        // address while the old primary's dev route still
                        // exists — and add_dev_route treats EEXIST as
                        // success, which would leave the new cell's
                        // return route pointing at the dying device.
                        // free() has the same ordering (destroy, then
                        // release).
                        let net = Arc::clone(net);
                        let cell_name = self.cell_name.clone();
                        let _ignored = handle.spawn(async move {
                            net.delete_primary_best_effort(&primary).await;
                            if let Err(e) = net.ipam.release(&key) {
                                warn!(
                                    "Cell {cell_name}: failed to release \
                                     IPAM slot: {e}"
                                );
                            }
                            info!(
                                "Cell {cell_name}: reclaimed host primary \
                                 `{primary}` on kill path"
                            );
                        });
                    }
                    (primary, _) => {
                        if let Some(primary) = primary {
                            // No runtime (process teardown): the kernel
                            // reaps the primary with the cell's netns, and
                            // nothing can re-allocate after this process
                            // exits — the route-collision window above
                            // doesn't apply.
                            warn!(
                                "Cell {}: no tokio runtime on kill path — \
                                 host primary `{primary}` is deleted only \
                                 when the cell netns is reaped",
                                self.cell_name
                            );
                        }
                        if let Err(e) = net.ipam.release(&key) {
                            warn!(
                                "Cell {}: failed to release IPAM slot: {e}",
                                self.cell_name
                            );
                        }
                    }
                }
            }

            teardown?;
        }

        self.state = CellState::Freed;
        Ok(())
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

/// Wait until the nested auraed's unix socket file exists. The child
/// creates this socket as the last step of `CellSystemRuntime::init`, so
/// its presence is a reliable "child finished startup" signal. We poll
/// the filesystem (the path is local; stat takes microseconds) rather
/// than connecting, because connecting forces the daemon to handle a TLS
/// handshake we don't actually need here — we only need to know the
/// child got past `init_endpoint`.
///
/// `AuraeSocket::Addr` is treated as "trivially ready" — that variant is
/// used for TCP, where the address is reachable immediately and the
/// blocking is on connect, not on socket-existence.
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

#[async_trait::async_trait]
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
    /// During normal behavior, cells are freed before being dropped,
    /// but cache reconciliation may result in a drop in other circumstances.
    /// Here we have a chance to clean up, no matter the circumstance.
    fn drop(&mut self) {
        // We use kill here to be aggressive in cleaning up if anything has
        // been left behind. kill is sync best-effort and reclaims the
        // guard/IPAM state inline; only the netlink deletion of the host
        // primary needs a runtime, and the primary dies with the cell's
        // netns anyway.
        let _best_effort = self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
