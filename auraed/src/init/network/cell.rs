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

//! Per-cell interface lifecycle. This module creates the netkit pair, binds
//! the cell source address, moves the peer into the cell network namespace, and removes
//! all of it again.
//!
//! The sequence of the steps is important. The source binding is installed
//! while the peer is still in the host network namespace and admin-down. Thus a cell
//! cannot send an unfiltered packet.

use super::bpf::SchedClassifierLink;
use super::netlink::{
    configure_routed_endpoint, get_link_index, netlink_errno,
};
use super::{Network, NetworkError};
use crate::cells::cell_service::cells::CellName;
use crate::init::network::ipam::Allocation;
use ipnet::Ipv6Net;
use netlink_packet_route::link::{NetkitMode, NetkitPolicy};
use nix::libc;
use rtnetlink::{LinkNetkit, LinkUnspec};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use tracing::{info, trace, warn};

/// Host-side state for the interface of one cell. The destroy, hard-kill,
/// and rollback paths use it to undo `create_cell_interface`.
#[derive(Clone)]
pub(super) struct CellInterfaceState {
    /// Name of the netkit primary in the host network namespace, such as `nk-a1b2c3d4`.
    primary: String,
    /// The delegated prefix of the cell. It is half of the `cell_src`
    /// binding.
    delegated: Ipv6Net,
    /// Index used by the eBPF policy and redirect maps.
    ifindex: u32,
    /// Keeps the target network namespace alive if the child exits. The
    /// kernel-managed target map separately detects explicit link deletion.
    _peer_netns: Arc<OwnedFd>,
    /// Cleanup flags are shared by snapshots of this state so each successful
    /// step remains complete across asynchronous teardown and retries.
    enforcement: Arc<Mutex<CellEnforcementState>>,
}

struct CellEnforcementState {
    /// Owns the tcx attachment until source cleanup begins.
    bpf_link: Option<SchedClassifierLink>,
    bpf_armed: bool,
    nft_bound: bool,
    /// Non-reused key in the kernel's identity-bearing target map.
    redirect_id: Option<u32>,
}

impl Network {
    /// Reserve a unique `(primary, peer)` name pair. This function creates
    /// no interfaces. The caller reserves the names before it starts the
    /// nested auraed, because the child receives the peer name in an
    /// environment variable. The caller then gives the same names to
    /// [`Self::create_cell_interface`].
    ///
    /// Each name has a random 8-character hexadecimal suffix.
    /// Examples are `nk-a1b2c3d4` and peer `nk-a1b2c3d4-p`.
    /// Both names are shorter than IFNAMSIZ (16).
    /// A 32-bit range is sufficient for usual cell counts.
    pub(crate) fn reserve_interface_names(&self) -> (String, String) {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let primary = format!("nk-{}", &suffix[..8]);
        let peer = format!("{primary}-p");
        (primary, peer)
    }

    /// Create an interface pair for a cell. This function moves the peer
    /// into `peer_netns_fd`, the network namespace of the cell. The nested auraed in
    /// that network namespace then configures the peer with [`Self::init_endpoint`].
    ///
    /// Steps:
    /// 1. Create the pair as a netkit device in L3 mode. An L3 pair carries
    ///    IP only. It has no MAC address, no ARP or ND, and no DAD
    ///    (`ARPHRD_NONE` and `IFF_NOARP`). Both ends need the `Pass`
    ///    policy, because a `Drop` policy stops the packets before the RX
    ///    path of the primary, where the host tc programs run.
    /// 2. Bind `(primary, delegated prefix)` in the nft `cell_src` set.
    ///    This step occurs before the peer enters the network namespace of the cell.
    ///    Thus the cell cannot send unfiltered traffic. A failure here is
    ///    fatal for the cell. Do not supply an unbound interface.
    /// 3. Move the peer into `peer_netns_fd`.
    /// 4. Give the host-side primary the address `host_ip/128` and set the
    ///    link up.
    /// 5. Add a `dev` route for the delegated guest prefix through the
    ///    primary, so that return traffic reaches the host stack.
    /// 6. Record the host-side state in `cell_interfaces` for
    ///    `destroy_cell_interface`.
    ///
    /// If a step after step 1 fails, this function removes the binding and
    /// deletes the primary, so that the pair does not leak. The kernel
    /// deletes the orphan peer together with its primary.
    pub(crate) async fn create_cell_interface(
        &self,
        cell_name: &CellName,
        allocation: &Allocation,
        peer_netns_fd: OwnedFd,
        primary: &str,
        peer: &str,
    ) -> Result<(), NetworkError> {
        // Create the interface pair on the host. Both halves start in this
        // network namespace. The peer moves next. After this point each failure must
        // delete the primary to prevent a leak.
        self.inner
            .handle
            .link()
            .add(
                LinkNetkit::new(primary, peer, NetkitMode::L3)
                    .policy(NetkitPolicy::Pass)
                    .peer_policy(NetkitPolicy::Pass)
                    .build(),
            )
            .execute()
            .await
            .map_err(|e| NetworkError::ErrorCreatingInterface {
                primary: primary.to_string(),
                peer: peer.to_string(),
                source: e,
            })?;

        let ifindex =
            match get_link_index(&self.inner.handle, primary.to_string()).await
            {
                Ok(index) => index,
                Err(error) => {
                    self.delete_primary_best_effort(primary).await;
                    return Err(error);
                }
            };

        // The nft binding below is the mandatory source policy. Arm the BPF
        // accelerator when it is available, but preserve the nft/host-stack
        // path if loading or attachment is unsupported on this host.
        let bpf_link = match self.inner.cell_guard.get() {
            Some(cell_guard) => {
                match cell_guard.arm_for_cell(
                    primary,
                    ifindex,
                    allocation.delegated,
                ) {
                    Ok(link) => Some(link),
                    Err(error) => {
                        warn!(
                            "Cell interface `{primary}`: cell-net BPF attach \
                             failed: {error}. Using nft/host-stack mode."
                        );
                        None
                    }
                }
            }
            None => None,
        };

        let peer_netns = Arc::new(peer_netns_fd);
        let bpf_armed = bpf_link.is_some();
        // Track the pair before a later operation can fail.
        let state = CellInterfaceState {
            primary: primary.to_string(),
            delegated: allocation.delegated,
            ifindex,
            _peer_netns: peer_netns.clone(),
            enforcement: Arc::new(Mutex::new(CellEnforcementState {
                bpf_link,
                bpf_armed,
                nft_bound: false,
                redirect_id: None,
            })),
        };
        let tracked = match self.inner.cell_interfaces.lock() {
            Ok(mut guard) => {
                let _ = guard.insert(cell_name.clone(), state.clone());
                true
            }
            Err(_poisoned) => false,
        };
        if !tracked {
            {
                let mut enforcement = state
                    .enforcement
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let link = enforcement.bpf_link.take();
                if enforcement.bpf_armed
                    && let Some(cell_guard) = self.inner.cell_guard.get()
                    && let Err(error) = cell_guard.disarm_source(ifindex, link)
                {
                    warn!(
                        "Rollback: failed to disarm cell-net BPF for \
                         `{primary}` (ifindex {ifindex}): {error}"
                    );
                }
            }
            self.delete_primary_best_effort(primary).await;
            return Err(NetworkError::CellInterfacesPoisoned);
        }

        // Bind the cell source in nftables while the peer is still in the
        // host network namespace and admin-down. Thus the cell cannot send an
        // unfiltered packet. A failure here is fatal for the cell, because
        // an unbound interface can forge the address of a sibling.
        if let Err(e) =
            self.inner.nat.bind_cell_source(primary, allocation.delegated)
        {
            let setup_error = NetworkError::FailedToConnect(e);
            return match self.destroy_cell_interface(cell_name).await {
                Ok(()) => Err(setup_error),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
        {
            let guard = self
                .inner
                .cell_interfaces
                .lock()
                .map_err(|_| NetworkError::CellInterfacesPoisoned)?;
            if let Some(state) = guard.get(cell_name) {
                state
                    .enforcement
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .nft_bound = true;
            }
        }

        // Move the peer into the network namespace of the cell. Each cell has a unique
        // peer name. Thus the peer name cannot conflict with an interface
        // name in the host network namespace before the move.
        let setup_result: Result<(), NetworkError> = async {
            let peer_msg = LinkUnspec::new_with_name(peer)
                .setns_by_fd(peer_netns.as_raw_fd())
                .build();
            self.inner.handle.link().set(peer_msg).execute().await.map_err(
                |e| NetworkError::ErrorMovingLinkToNetns {
                    iface: peer.to_string(),
                    source: e,
                },
            )?;

            // Configure the routed host endpoint.
            configure_routed_endpoint(
                &self.inner.handle,
                primary,
                allocation.host_ip,
                allocation.delegated,
            )
            .await?;
            Ok(())
        }
        .await;

        if let Err(e) = setup_result {
            return match self.destroy_cell_interface(cell_name).await {
                Ok(()) => Err(e),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }

        let guard_mode = if bpf_armed { "bpf" } else { "nft" };
        info!(
            "Created cell interface for {cell_name}: primary={primary} \
             peer={peer}, host={}, guest={} (guard={guard_mode})",
            allocation.host_ip, allocation.guest_ip,
        );
        Ok(())
    }

    /// Remove both source-enforcement layers. Each successful step updates
    /// shared state, all pending steps are attempted, and the first failure
    /// is returned so a later teardown can retry only what remains.
    fn cleanup_cell_enforcement(
        &self,
        state: &CellInterfaceState,
    ) -> Result<(), NetworkError> {
        let mut enforcement =
            state.enforcement.lock().unwrap_or_else(|poisoned| {
                warn!(
                    "Cell interface `{}` enforcement mutex poisoned; \
                     recovering for cleanup",
                    state.primary
                );
                poisoned.into_inner()
            });
        let mut first_error = None;

        if enforcement.nft_bound {
            match self
                .inner
                .nat
                .unbind_cell_source(&state.primary, state.delegated)
            {
                Ok(()) => enforcement.nft_bound = false,
                Err(source) => {
                    first_error = Some(NetworkError::FailedToConnect(source));
                }
            }
        }

        if enforcement.bpf_armed {
            let link = enforcement.bpf_link.take();
            let result = match self.inner.cell_guard.get() {
                Some(cell_guard) => cell_guard
                    .disarm_source(state.ifindex, link)
                    .map_err(|source| NetworkError::BpfGuardFailed {
                        iface: state.primary.clone(),
                        source: Box::new(source),
                    }),
                None => Err(NetworkError::GuardNotLoaded {
                    iface: state.primary.clone(),
                }),
            };
            match result {
                Ok(()) => enforcement.bpf_armed = false,
                Err(error) if first_error.is_none() => {
                    first_error = Some(error);
                }
                Err(error) => warn!(
                    "Additional cleanup failure for cell interface `{}`: \
                     {error}",
                    state.primary
                ),
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Publish a ready cell as a target of the eBPF redirect fast path.
    pub(crate) fn publish_cell_redirect(
        &self,
        cell_name: &CellName,
    ) -> Result<(), NetworkError> {
        let state = {
            let guard = self
                .inner
                .cell_interfaces
                .lock()
                .map_err(|_| NetworkError::CellInterfacesPoisoned)?;
            guard.get(cell_name).cloned()
        };
        let Some(state) = state else { return Ok(()) };
        let mut enforcement = state
            .enforcement
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !enforcement.bpf_armed || enforcement.redirect_id.is_some() {
            return Ok(());
        }
        let Some(cell_guard) = self.inner.cell_guard.get() else {
            return Err(NetworkError::GuardNotLoaded { iface: state.primary });
        };
        let redirect_id = cell_guard
            .publish_redirect(state.ifindex, state.delegated)
            .map_err(|source| NetworkError::BpfGuardFailed {
                iface: format!("ifindex {}", state.ifindex),
                source: Box::new(source),
            })?;
        enforcement.redirect_id = Some(redirect_id);
        info!(
            "Published cell-to-cell BPF fast path for {cell_name}: \
             primary={}, delegated={}, redirect_id={redirect_id}",
            state.primary, state.delegated
        );
        Ok(())
    }

    /// Stop directing sibling traffic at a cell. This must succeed before
    /// the child process is stopped or its netkit primary is deleted.
    pub(crate) fn unpublish_cell_redirect(
        &self,
        cell_name: &CellName,
    ) -> Result<(), NetworkError> {
        let state = {
            let guard = self
                .inner
                .cell_interfaces
                .lock()
                .map_err(|_| NetworkError::CellInterfacesPoisoned)?;
            guard.get(cell_name).cloned()
        };
        let Some(state) = state else { return Ok(()) };
        let mut enforcement = state
            .enforcement
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(redirect_id) = enforcement.redirect_id else {
            return Ok(());
        };
        let Some(cell_guard) = self.inner.cell_guard.get() else {
            return Err(NetworkError::GuardNotLoaded { iface: state.primary });
        };
        cell_guard.unpublish_redirect(state.delegated, redirect_id).map_err(
            |source| NetworkError::BpfGuardFailed {
                iface: format!("ifindex {}", state.ifindex),
                source: Box::new(source),
            },
        )?;
        enforcement.redirect_id = None;
        Ok(())
    }

    /// Delete a host-side primary by name. The function is best-effort.
    /// The rollback path of `create_cell_interface` and the hard-kill path
    /// use it. The function logs errors and does not return them, because
    /// the callers are on a failure path and must keep the initial cause.
    pub(crate) async fn delete_primary_best_effort(&self, primary: &str) {
        match get_link_index(&self.inner.handle, primary.to_string()).await {
            Ok(idx) => {
                match self.inner.handle.link().del(idx).execute().await {
                    Ok(()) => {}
                    // The kernel deletes the pair when the network namespace of the
                    // cell ends. That can occur before this delete.
                    Err(e) if netlink_errno(&e) == Some(-libc::ENODEV) => {
                        trace!(
                            "Primary `{primary}` disappeared before delete \
                             (netns teardown won the race)"
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Rollback: failed to delete primary `{primary}` \
                             (index {idx}): {e}. Host interface may leak."
                        );
                    }
                }
            }
            Err(NetworkError::DeviceNotFound { .. }) => {
                // The primary is already gone.
            }
            Err(e) => {
                warn!(
                    "Rollback: could not look up primary `{primary}` for \
                     deletion: {e}. Host interface may leak."
                );
            }
        }
    }

    /// Remove the host link and the source binding for a cell.
    ///
    /// The function keeps the state until each cleanup step succeeds.
    pub(crate) async fn destroy_cell_interface(
        &self,
        cell_name: &CellName,
    ) -> Result<(), NetworkError> {
        let state = {
            let guard = self
                .inner
                .cell_interfaces
                .lock()
                .map_err(|_| NetworkError::CellInterfacesPoisoned)?;
            guard.get(cell_name).cloned()
        };
        let Some(state) = state else { return Ok(()) };
        let primary = &state.primary;

        // Remove both publication maps before deleting the target. The
        // target map also fails safely if the peer was explicitly deleted.
        self.unpublish_cell_redirect(cell_name)?;

        let index = match get_link_index(&self.inner.handle, primary.clone())
            .await
        {
            Ok(idx) => idx,
            Err(NetworkError::DeviceNotFound { .. }) => {
                trace!(
                    "destroy_cell_interface: primary `{primary}` already gone \
                     for cell {cell_name}"
                );
                0
            }
            Err(e) => return Err(e),
        };

        if index != 0 {
            match self.inner.handle.link().del(index).execute().await {
                Ok(()) => {}
                Err(e) if netlink_errno(&e) == Some(-libc::ENODEV) => {}
                Err(e) => {
                    return Err(NetworkError::ErrorDeletingLink {
                        iface: primary.clone(),
                        index,
                        source: e,
                    });
                }
            }
        }

        self.cleanup_cell_enforcement(&state)?;
        let mut guard = self
            .inner
            .cell_interfaces
            .lock()
            .map_err(|_| NetworkError::CellInterfacesPoisoned)?;
        let _ = guard.remove(cell_name);
        info!(
            "Destroyed cell interface for {cell_name}: primary={primary} \
             index={index}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::netlink::get_link_index;
    use super::super::testutil::*;
    use super::super::{Network, ipam::IpamConfig};
    use super::*;
    use serial_test::serial;
    use test_helpers::*;

    /// The kernel returns ENODEV if a link is gone between the lookup and
    /// the delete. The tolerant delete paths use this classification.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // Serialized: mutates global host netlink state.
    #[serial]
    async fn delete_tolerates_already_gone_device() {
        skip_if_not_root!("delete_tolerates_already_gone_device");
        skip_if_seccomp!("delete_tolerates_already_gone_device");

        let network =
            Network::connect(IpamConfig::default()).expect("netlink connect");
        let handle = &network.inner.handle;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let primary = format!("tst-{}", &suffix[..8]);
        let peer = format!("{primary}-p");

        create_test_pair(handle, &primary, &peer).await;
        let idx = get_link_index(handle, primary.clone())
            .await
            .expect("test pair exists");
        handle.link().del(idx).execute().await.expect("first delete");

        let err = handle
            .link()
            .del(idx)
            .execute()
            .await
            .expect_err("device is already gone");
        assert_eq!(netlink_errno(&err), Some(-libc::ENODEV));

        // The best-effort path stays silent on an already-gone primary.
        network.delete_primary_best_effort(&primary).await;
    }
}
