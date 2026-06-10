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

use futures::stream::TryStreamExt;
use ipnet::{IpNet, Ipv6Net};
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::{
    InfoKind, LinkAttribute, LinkFlags, LinkInfo, NetkitMode, NetkitPolicy,
};
use netlink_packet_route::route::RouteAttribute;
use nix::libc;
use rtnetlink::{Handle, LinkNetkit, LinkUnspec, RouteMessageBuilder};
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::os::fd::RawFd;
use std::str;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{error, info, trace, warn};

use crate::cells::cell_service::cells::CellName;
use crate::init::network::endpoint::NetworkConfig;
use crate::init::network::ipam::{Allocation, Ipam, IpamConfig};

pub(crate) mod bpf;
pub(crate) mod endpoint;
pub(crate) mod ipam;
pub(crate) mod nat;
mod sriov;

use bpf::{CellNetGuard, SchedClassifierLink};
use nat::NatManager;

/// Outcome of [`Network::init_host_network`]. Callers consult this to decide
/// whether cell operations should be allowed and what to surface to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkReady {
    /// Sysctls set, NAT installed — endpoints can reach the internet.
    Full,
    /// Sysctls set but NAT could not be installed — endpoints can talk between
    /// themselves and to the host, but cannot reach the internet.
    LocalOnly,
    /// Network plumbing could not be initialized — endpoints cannot start.
    Unavailable,
}

impl NetworkReady {
    /// Cells with `isolate_network=true` can still allocate when only local
    /// connectivity exists — they reach each other and the host even without
    /// NAT egress.
    pub(crate) fn allows_cells(self) -> bool {
        matches!(self, NetworkReady::Full | NetworkReady::LocalOnly)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Failed to initialize network: {0}")]
    FailedToConnect(#[from] std::io::Error),
    #[error("Could not find link `{iface}`")]
    DeviceNotFound { iface: String },
    #[error("Error adding address `{ip}` to link `{iface}`: {source}")]
    ErrorAddingAddress { iface: String, ip: IpNet, source: rtnetlink::Error },
    #[error("Failed to set link up for device `{iface}`: {source}")]
    ErrorSettingLinkUp { iface: String, source: rtnetlink::Error },
    #[error("Failed to set link down for device `{iface}`: {source}")]
    ErrorSettingLinkDown { iface: String, source: rtnetlink::Error },
    #[error(
        "Error adding route from `{route_source}` to {route_destination}` for device `{iface}`: {source}"
    )]
    ErrorAddingRoute {
        iface: String,
        route_source: IpNet,
        route_destination: IpNet,
        source: rtnetlink::Error,
    },
    #[error("Failed to enable IP forwarding ({family}): {msg}")]
    ErrorEnablingIpForwarding { family: &'static str, msg: String },
    #[error(
        "Failed to create interface pair `{primary}` <-> `{peer}`: {source}"
    )]
    ErrorCreatingInterface {
        primary: String,
        peer: String,
        source: rtnetlink::Error,
    },
    #[error("Failed to move link `{iface}` into target netns: {source}")]
    ErrorMovingLinkToNetns { iface: String, source: rtnetlink::Error },
    #[error("Failed to delete link `{iface}` (index {index}): {source}")]
    ErrorDeletingLink { iface: String, index: u32, source: rtnetlink::Error },
    #[error(
        "Timed out waiting for link `{iface}` to appear after {timeout_ms} ms"
    )]
    TimedOutWaitingForLink { iface: String, timeout_ms: u64 },
    #[error(
        "cell_interfaces mutex poisoned — daemon network state is unrecoverable"
    )]
    CellInterfacesPoisoned,
    #[error("Failed to rename link `{old}` to `{new}`: {source}")]
    ErrorRenamingLink { old: String, new: String, source: rtnetlink::Error },
    #[error("Failed to enable cell-net BPF guard for `{iface}`: {source}")]
    BpfGuardFailed { iface: String, source: bpf::CellGuardError },
    #[error(transparent)]
    Other(#[from] rtnetlink::Error),
}

/// Host-side state for one cell's interface, tracked so the destroy,
/// hard-kill, and rollback paths can undo everything `create_cell_interface`
/// set up.
struct CellInterfaceState {
    /// Name of the netkit primary in the host netns (e.g. `nk-a1b2c3d4`).
    primary: String,
    /// The primary's ifindex — the key for the guard's BPF map entries.
    ifindex: u32,
    /// The cell's delegated prefix — the guard's redirect-map key.
    delegated: Ipv6Net,
    /// Owned tc(x) link for the guard program on the primary; dropping it
    /// detaches the program. `None` when the daemon runs without the
    /// guard (eBPF object missing or failed to load).
    bpf_link: Option<SchedClassifierLink>,
}

/// Handle to the host's network plumbing. Owns the rtnetlink handle for
/// link/address/route operations, the [`NatManager`] for the daemon's nft
/// table, per-cell interface state, and the IPAM allocator. Embedding
/// everything here ties its lifetime to the daemon's `Network` instance —
/// no global state, and per-cell address bookkeeping coordinates 1:1 with
/// the interface primaries that own those addresses. The daemon's main loop
/// holds an `Arc<Network>` for the duration of the process; on drop,
/// [`Self::cleanup_host_network`] uninstalls the nft table.
pub(crate) struct Network {
    handle: Handle,
    /// Self-managing NAT lifecycle: tracks its own installed/uninstalled
    /// state and serializes install/uninstall internally.
    nat: NatManager,
    /// Per-cell host-side interface state (primary name, ifindex, guard
    /// link), keyed by cell name. The peer in the cell's netns disappears
    /// with the netns; only host-side state needs tracking for teardown.
    cell_interfaces: Mutex<HashMap<CellName, CellInterfaceState>>,
    /// The cell-net eBPF guard (per-cell anti-spoof + cell→cell
    /// redirect). Loaded once by [`Self::init_host_network`]; stays unset
    /// in cell-side contexts and when loading fails — cells then run
    /// without the guard, exactly as before it existed.
    cell_guard: OnceLock<CellNetGuard>,
    /// IPAM allocator. Self-locking; callers go directly to it for
    /// allocate/release. In cell-side contexts (where this `Network` is
    /// built but [`Self::init_host_network`] is never called), the
    /// allocator is unused.
    pub(crate) ipam: Ipam,
}

impl fmt::Debug for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Handle isn't Debug; report the nat installed/uninstalled state.
        let cell_count =
            self.cell_interfaces.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("Network")
            .field("nat_installed", &self.nat.is_installed())
            .field("cell_interface_count", &cell_count)
            .finish()
    }
}

impl Network {
    #[allow(clippy::result_large_err)]
    pub(crate) fn connect() -> Result<Network, NetworkError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        let _ignored = tokio::spawn(connection);
        Ok(Self {
            handle,
            nat: NatManager::new(),
            cell_interfaces: Mutex::new(HashMap::new()),
            cell_guard: OnceLock::new(),
            ipam: Ipam::default(),
        })
    }

    /// Initialize the host's networking plumbing for cells: enable v6
    /// forwarding, set `accept_ra=2` on the WAN, and install the IPv6
    /// `inet aurae` nft table for masquerade + anti-spoof. Stores the
    /// resulting [`NatManager`] in `self.nat` so
    /// [`Self::cleanup_host_network`] can tear it down at daemon shutdown.
    /// Does NOT touch any per-endpoint links.
    ///
    /// Sysctl mutations are not rolled back: reverting `forwarding=1` or
    /// `accept_ra=2` at shutdown could break the host's connectivity (e.g.
    /// a SLAAC-learned default route) right as the daemon stops.
    pub(crate) async fn init_host_network(
        &self,
        ipam_config: IpamConfig,
    ) -> NetworkReady {
        let pool_v6 = ipam_config.pool_v6;

        if let Err(e) = enable_forwarding_v6() {
            error!(
                "Failed to enable IPv6 forwarding: {e}. Endpoints cannot start."
            );
            return NetworkReady::Unavailable;
        }

        // Reconcile leftover per-cell state from a previous daemon
        // before anything can collide with it (the fresh IPAM will
        // re-hand-out addresses that leftover primaries still route).
        self.cleanup_leftover_cell_interfaces().await;

        // Load the cell-net guard before the LocalOnly early-returns:
        // hosts without internet egress still allocate cells and want
        // per-cell anti-spoof + cell→cell redirect. Failure degrades to
        // guard-less operation (the pre-guard behavior) rather than
        // blocking the daemon.
        match CellNetGuard::load() {
            Ok(guard) => {
                let _ = self.cell_guard.set(guard);
                info!(
                    "Loaded cell-net BPF guard (per-cell anti-spoof + \
                     cell-to-cell redirect)"
                );
            }
            Err(e) => {
                warn!(
                    "Cell-net BPF guard unavailable ({e}); cells will run \
                     without per-cell anti-spoof and the cell-to-cell fast \
                     path. Run `make ebpf` to install the eBPF programs."
                );
            }
        }

        if !self.has_gateway_v6().await {
            warn!(
                "Host has no IPv6 default route — endpoints will not have v6 \
                 internet egress. Local connectivity between endpoints \
                 and the host still works."
            );
            return NetworkReady::LocalOnly;
        }

        let wan_iface = match self.get_default_route_iface().await {
            Some(iface) => iface,
            None => {
                error!(
                    "Host reported a default route but no default-route \
                     interface could be located. Skipping NAT setup; endpoints \
                     will not have internet egress."
                );
                return NetworkReady::LocalOnly;
            }
        };

        if let Err(e) = set_accept_ra_router_mode(&wan_iface) {
            warn!(
                "Failed to set accept_ra=2 on '{wan_iface}': {e}. \
                 NAT install will still proceed but the host's IPv6 \
                 default route may expire after RA timeout."
            );
        }

        if let Err(e) = self.nat.install(pool_v6, &wan_iface) {
            warn!(
                "Failed to install NAT ruleset for '{wan_iface}': {e}. \
                 Endpoints will not have internet egress."
            );
            return NetworkReady::LocalOnly;
        }
        info!("Installed NAT ruleset for v6={pool_v6} via '{wan_iface}'");
        NetworkReady::Full
    }

    /// Tear down the daemon's NAT ruleset. No-op when nothing is
    /// installed. Also runs from [`Drop`] so the daemon doesn't have to
    /// call this explicitly.
    pub(crate) fn cleanup_host_network(&self) {
        if let Err(e) = self.nat.uninstall() {
            warn!("Failed to uninstall NAT ruleset: {e}");
        }
    }

    /// True iff the host has an IPv6 default route.
    pub(crate) async fn has_gateway_v6(&self) -> bool {
        let route_msg = RouteMessageBuilder::<Ipv6Addr>::new().build();
        let mut routes = self.handle.route().get(route_msg).execute();
        while let Ok(Some(route)) = routes.try_next().await {
            if route.header.destination_prefix_length == 0
                && route.header.address_family == AddressFamily::Inet6
            {
                let has_oif = route
                    .attributes
                    .iter()
                    .any(|attr| matches!(attr, RouteAttribute::Oif(_)));
                if has_oif {
                    return true;
                }
            }
        }
        false
    }

    /// Reserve a unique `(primary, peer)` name pair without creating
    /// anything yet. Callers use this to pick names BEFORE spawning the
    /// nested auraed (so the peer name can be passed via env var to the
    /// child) and pass the same names back to
    /// [`Self::create_cell_interface`] when they're ready to actually
    /// create the pair.
    ///
    /// The peer name is intentionally NOT `eth0` — that would collide with
    /// the host's own `eth0` while both halves still live in the parent
    /// netns. The child renames the peer to `eth0` once it lands in the
    /// cell's netns (where the name is local).
    ///
    /// Names use a random 8-hex-char suffix (`nk-a1b2c3d4`, peer
    /// `nk-a1b2c3d4-p`). Both fit comfortably under IFNAMSIZ (16).
    /// 32-bit collision space is plenty for typical cell counts.
    pub(crate) fn reserve_interface_names(&self) -> (String, String) {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let primary = format!("nk-{}", &suffix[..8]);
        let peer = format!("{primary}-p");
        (primary, peer)
    }

    /// Create an interface pair for a cell. Host-side work only — the peer
    /// is moved into `peer_netns_fd` (the cell's netns) immediately after
    /// creation, where the nested auraed inside that netns picks it up via
    /// [`Self::init_endpoint`].
    ///
    /// `primary` and `peer` must be the names returned by
    /// [`Self::reserve_interface_names`] for this cell. They live in
    /// `IFNAMSIZ`-bounded space; the peer name is unique-per-cell so it
    /// can't collide with the host's `eth0` while both halves are still
    /// in the parent netns.
    ///
    /// Steps:
    /// 1. Build the interface pair (netkit in L3 mode — a pure-IP pair
    ///    with no MACs, no ARP/ND, and no DAD (`ARPHRD_NONE` +
    ///    `IFF_NOARP`). The `Pass` policy on both ends is required:
    ///    packets must reach the primary's RX path where the host's tc
    ///    programs run — a `Drop` device policy would starve them).
    /// 2. Activate the cell-net guard on the primary (when loaded):
    ///    insert the cell's policy/redirect/stats map entries, then
    ///    attach the classifier at tc(x) ingress. This happens BEFORE
    ///    the peer enters the cell's netns, so the cell can never emit
    ///    unfiltered traffic. A guard failure is fatal for the cell —
    ///    when the guard exists we never hand out an unguarded
    ///    interface.
    /// 3. Move the peer into `peer_netns_fd`.
    /// 4. Configure the host-side primary with `host_ip/128` and bring
    ///    it up.
    /// 5. Add a `dev` route for the delegated guest prefix via the primary
    ///    so return traffic from the cell reaches the host stack.
    /// 6. Track the host-side state in `cell_interfaces` so
    ///    `destroy_cell_interface` can find it later.
    ///
    /// On failure of any step after step 1, the guard state (if any) is
    /// torn down and the primary is deleted so the pair doesn't leak.
    /// The kernel removes the orphaned peer along with its primary.
    pub(crate) async fn create_cell_interface(
        &self,
        cell_name: &CellName,
        allocation: &Allocation,
        peer_netns_fd: RawFd,
        primary: &str,
        peer: &str,
    ) -> Result<(), NetworkError> {
        // 1. Create the interface pair on the host. Both halves start in
        //    this netns; the peer is moved next. From this point on, any
        //    failure must delete the primary to avoid a leak.
        self.handle
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
            match get_link_index(&self.handle, primary.to_string()).await {
                Ok(idx) => idx,
                Err(e) => {
                    self.delete_primary_best_effort(primary).await;
                    return Err(e);
                }
            };

        // 2. Activate the guard while the peer is still in the host netns
        //    and admin-down — no packet can cross the pair before the
        //    program is attached.
        let mut bpf_link = None;
        if let Some(cell_guard) = self.cell_guard.get() {
            match cell_guard.enable_for_cell(
                primary,
                ifindex,
                allocation.delegated,
            ) {
                Ok(link) => bpf_link = Some(link),
                Err(source) => {
                    self.delete_primary_best_effort(primary).await;
                    return Err(NetworkError::BpfGuardFailed {
                        iface: primary.to_string(),
                        source,
                    });
                }
            }
        }

        // 3. Move the peer into the cell's netns. The peer name is
        //    unique-per-cell so it doesn't collide with the host's
        //    `eth0` (or any other interface) before the move.
        let setup_result: Result<(), NetworkError> = async {
            let peer_msg = LinkUnspec::new_with_name(peer)
                .setns_by_fd(peer_netns_fd)
                .build();
            self.handle.link().set(peer_msg).execute().await.map_err(|e| {
                NetworkError::ErrorMovingLinkToNetns {
                    iface: peer.to_string(),
                    source: e,
                }
            })?;

            // 4 & 5: configure the routed host endpoint.
            configure_routed_endpoint(
                &self.handle,
                primary,
                allocation.host_ip,
                allocation.delegated,
            )
            .await?;
            Ok(())
        }
        .await;

        if let Err(e) = setup_result {
            // Roll back: deactivate the guard, then delete the primary.
            // The kernel removes the peer along with it (whether still
            // local or already in the cell netns — orphaned interface
            // halves are reaped).
            if let Some(cell_guard) = self.cell_guard.get() {
                cell_guard.disable_for_cell(
                    ifindex,
                    allocation.delegated,
                    bpf_link.take(),
                );
            }
            self.delete_primary_best_effort(primary).await;
            return Err(e);
        }

        // 6. Track the host-side state so destroy_cell_interface can find
        //    it. If the mutex is poisoned the daemon is in an unrecoverable
        //    state — bail and roll back rather than leak.
        let state = CellInterfaceState {
            primary: primary.to_string(),
            ifindex,
            delegated: allocation.delegated,
            bpf_link,
        };
        let track_result = match self.cell_interfaces.lock() {
            Ok(mut guard) => {
                let _ = guard.insert(cell_name.clone(), state);
                Ok(())
            }
            Err(_poisoned) => Err(NetworkError::CellInterfacesPoisoned),
        };

        if let Err(e) = track_result {
            error!(
                "cell_interfaces mutex poisoned — rolling back interface `{primary}`"
            );
            if let Some(cell_guard) = self.cell_guard.get() {
                // The link lives in `state`, which drops when this
                // function returns (detaching the program); only the map
                // entries need explicit removal here.
                cell_guard.disable_for_cell(
                    ifindex,
                    allocation.delegated,
                    None,
                );
            }
            self.delete_primary_best_effort(primary).await;
            return Err(e);
        }

        info!(
            "Created cell interface for {cell_name}: primary={primary} \
             peer={peer}, host={}, guest={}, guard={}",
            allocation.host_ip,
            allocation.guest_ip,
            if self.cell_guard.get().is_some() { "on" } else { "off" },
        );
        Ok(())
    }

    /// Best-effort delete of a host-side interface primary by name. Used
    /// from `create_cell_interface`'s rollback path and the hard-kill
    /// reclamation path. Errors are logged rather than propagated — the
    /// callers are already on failure paths and would lose the original
    /// cause if we replaced it.
    pub(crate) async fn delete_primary_best_effort(&self, primary: &str) {
        match get_link_index(&self.handle, primary.to_string()).await {
            Ok(idx) => {
                match self.handle.link().del(idx).execute().await {
                    Ok(()) => {}
                    // The kernel reaps the pair when the cell's netns
                    // dies, racing this delete — already gone is fine.
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
                // Primary already gone — nothing to do.
            }
            Err(e) => {
                warn!(
                    "Rollback: could not look up primary `{primary}` for \
                     deletion: {e}. Host interface may leak."
                );
            }
        }
    }

    /// Best-effort sweep of leftover cell primaries from a previous
    /// daemon. A crash/SIGKILL leaves orphaned nested auraeds running
    /// (they're spawned without `PDEATHSIG`), and their netnses keep the
    /// host-side `nk-*` primaries and `/128` dev routes alive — while
    /// this daemon's in-memory IPAM restarts from scratch and re-hands
    /// out the very same addresses. Deleting the leftover primaries
    /// severs those orphans (the daemon owns all cell plumbing; the
    /// orphans already lost their BPF guard when the old daemon's links
    /// died with its fds) and frees their routes. Same philosophy as the
    /// NAT delete-before-install.
    ///
    /// Matches only netkit-kind devices named `nk-<8 hex>` — the
    /// namespace [`Self::reserve_interface_names`] owns. Assumes a
    /// single auraed daemon per host (the NAT table already does).
    async fn cleanup_leftover_cell_interfaces(&self) {
        let mut links = self.handle.link().get().execute();
        let mut leftovers: Vec<(u32, String)> = Vec::new();
        loop {
            match links.try_next().await {
                Ok(Some(link)) => {
                    let mut name = None;
                    let mut is_netkit = false;
                    for attr in &link.attributes {
                        match attr {
                            LinkAttribute::IfName(n) => name = Some(n.clone()),
                            LinkAttribute::LinkInfo(infos) => {
                                is_netkit = infos.iter().any(|info| {
                                    matches!(
                                        info,
                                        LinkInfo::Kind(InfoKind::Netkit)
                                    )
                                });
                            }
                            _ => {}
                        }
                    }
                    if let Some(name) = name
                        && is_netkit
                        && is_cell_primary_name(&name)
                    {
                        leftovers.push((link.header.index, name));
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(
                        "Leftover cell-interface sweep failed to dump links: \
                         {e}. Stale primaries from a previous daemon may \
                         shadow new cell routes."
                    );
                    return;
                }
            }
        }

        for (index, name) in leftovers {
            match self.handle.link().del(index).execute().await {
                Ok(()) => {
                    info!(
                        "Reclaimed leftover cell primary `{name}` \
                         (index {index}) from a previous daemon"
                    );
                }
                Err(e) if netlink_errno(&e) == Some(-libc::ENODEV) => {}
                Err(e) => {
                    warn!(
                        "Failed to reclaim leftover cell primary `{name}` \
                         (index {index}): {e}"
                    );
                }
            }
        }
    }

    /// Synchronously reclaim a cell's guard state: remove the tracking
    /// entry, detach the guard link, and remove the cell's BPF map
    /// entries. Returns the primary's name so the caller can delete the
    /// link itself (async); `None` when the cell had no interface.
    ///
    /// Split from [`Self::destroy_cell_interface`] so non-async paths
    /// (hard-kill, drop) can reclaim everything except the netlink
    /// deletion — and the primary usually dies with the cell's netns
    /// anyway.
    pub(crate) fn reclaim_cell_interface_sync(
        &self,
        cell_name: &CellName,
    ) -> Option<String> {
        let mut state = match self.cell_interfaces.lock() {
            Ok(mut guard) => guard.remove(cell_name)?,
            Err(_poisoned) => {
                error!(
                    "cell_interfaces mutex poisoned — cannot remove entry for \
                     {cell_name}. Host-side primary will leak."
                );
                return None;
            }
        };

        if let Some(cell_guard) = self.cell_guard.get() {
            cell_guard.disable_for_cell(
                state.ifindex,
                state.delegated,
                state.bpf_link.take(),
            );
        }
        Some(state.primary)
    }

    /// Tear down the host-side interface primary for a cell. The peer
    /// disappears with the cell's netns (kernel removes orphaned
    /// interface halves), and the kernel removes routes referring to a
    /// deleted link automatically — so this only needs to reclaim the
    /// guard state and delete the primary.
    pub(crate) async fn destroy_cell_interface(
        &self,
        cell_name: &CellName,
    ) -> Result<(), NetworkError> {
        let Some(primary) = self.reclaim_cell_interface_sync(cell_name) else {
            // No-op: cell had no interface (e.g. isolate_network=false, or
            // create_cell_interface failed before insert), or the
            // tracking mutex is poisoned (already logged).
            trace!(
                "destroy_cell_interface: no interface handles for cell {cell_name}"
            );
            return Ok(());
        };

        let index = match get_link_index(&self.handle, primary.clone()).await {
            Ok(idx) => idx,
            Err(NetworkError::DeviceNotFound { .. }) => {
                trace!(
                    "destroy_cell_interface: primary `{primary}` already gone \
                     for cell {cell_name}"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match self.handle.link().del(index).execute().await {
            Ok(()) => {}
            // The kernel reaps the pair when the cell's netns dies (the
            // nested auraed was just shut down), and that races this
            // delete: ENODEV between the lookup above and here means the
            // primary is already gone — which is the goal.
            Err(e) if netlink_errno(&e) == Some(-libc::ENODEV) => {
                trace!(
                    "destroy_cell_interface: primary `{primary}` disappeared \
                     before delete for cell {cell_name} (netns teardown won \
                     the race)"
                );
                return Ok(());
            }
            Err(e) => {
                return Err(NetworkError::ErrorDeletingLink {
                    iface: primary.clone(),
                    index,
                    source: e,
                });
            }
        }
        info!(
            "Destroyed cell interface for {cell_name}: primary={primary} \
             index={index}"
        );
        Ok(())
    }

    /// Bring up the local NIC for an auraed running in its own netns.
    /// Used by both Cell (true netns) and Pid1 (VM kernel netns) runtimes.
    /// `self.handle` is bound to the caller's netns.
    ///
    /// Steps:
    /// 1. Bring up loopback. Fresh netnses get `lo` down by default;
    ///    apps that bind localhost would otherwise fail.
    /// 2. Wait up to 5s for a link with `config.interface_name` to appear.
    ///    Cells get a parent-chosen unique name (`nk-<hex>-p`) that the
    ///    parent moves into this netns; VMs typically have `eth0`
    ///    available immediately. Polling is good enough here: rtnetlink
    ///    calls finish in ms; if this becomes flaky under load, swap to
    ///    RTNLGRP_LINK netlink notifications.
    /// 3. Rename `interface_name` → `eth0` if it isn't already. The
    ///    unique outer name avoided a collision with the host's `eth0`;
    ///    now that we're isolated in our own netns, `eth0` is free and
    ///    that's the conventional name for the primary NIC. No-op when
    ///    the source name is already `eth0` (typical VM scenario).
    /// 4. Bring `eth0` up.
    /// 5. Add `guest_v6/<prefix>` to `eth0`.
    /// 6. Add an `onlink` default route via the host gateway. `onlink` is
    ///    required because the gateway address sits outside the bound
    ///    prefix.
    ///
    /// Cell endpoints are netkit peers in L3 mode: `ARPHRD_NONE`,
    /// `IFF_NOARP`, no MAC and no link-local address. The `via` gateway
    /// still works because neighbours on NOARP devices are `NUD_NOARP` —
    /// the kernel never tries to resolve a link-layer address and queues
    /// packets straight to the device.
    pub(crate) async fn init_endpoint(
        &self,
        config: &NetworkConfig,
    ) -> Result<(), NetworkError> {
        const ETH0: &str = "eth0";
        const TIMEOUT: Duration = Duration::from_secs(5);
        const POLL: Duration = Duration::from_millis(50);

        configure_loopback(&self.handle).await?;

        wait_for_link(&self.handle, &config.interface_name, TIMEOUT, POLL)
            .await?;
        if config.interface_name != ETH0 {
            rename_link(&self.handle, &config.interface_name, ETH0).await?;
        }

        set_link_up(&self.handle, ETH0.to_string()).await?;

        let addr = Ipv6Net::new(config.guest_v6, config.guest_prefix_len_v6)
            .map_err(|e| {
                NetworkError::Other(rtnetlink::Error::NamespaceError(
                    e.to_string(),
                ))
            })?;
        add_address(&self.handle, ETH0.to_string(), addr).await?;

        add_onlink_default(&self.handle, ETH0, config.host_v6, config.guest_v6)
            .await?;

        info!(
            "Configured endpoint (source={}→{ETH0}): \
             guest={}/{}, default via {}",
            config.interface_name,
            config.guest_v6,
            config.guest_prefix_len_v6,
            config.host_v6,
        );
        Ok(())
    }

    /// Get the interface name for the default route. Walks IPv6 routes only
    /// — cells are IPv6-only.
    async fn get_default_route_iface(&self) -> Option<String> {
        let route_msg = RouteMessageBuilder::<Ipv6Addr>::new().build();
        let mut routes = self.handle.route().get(route_msg).execute();
        while let Ok(Some(route)) = routes.try_next().await {
            if route.header.destination_prefix_length == 0
                && route.header.address_family == AddressFamily::Inet6
            {
                for attr in &route.attributes {
                    if let RouteAttribute::Oif(oif_index) = attr
                        && let Ok(name) =
                            get_link_name(&self.handle, *oif_index).await
                        && !name.is_empty()
                    {
                        return Some(name);
                    }
                }
            }
        }
        None
    }
}

impl Drop for Network {
    /// Best-effort NAT cleanup when the daemon's `Network` goes away.
    /// Tests that build a `Network` without ever calling
    /// [`Network::init_host_network`] hit this no-op path (`nat` is `None`).
    fn drop(&mut self) {
        self.cleanup_host_network();
    }
}

/// Configure a host-side routed endpoint: add `host/128`, bring the link
/// up, install a `dev` route for the delegated guest prefix via that link.
///
/// Used to set up host-side cell interfaces.
async fn configure_routed_endpoint(
    handle: &Handle,
    iface: &str,
    host: Ipv6Addr,
    delegated: Ipv6Net,
) -> Result<(), NetworkError> {
    let host_net = Ipv6Net::new(host, 128).expect("/128 is a valid prefix");
    add_address(handle, iface.to_string(), host_net).await?;

    set_link_up(handle, iface.to_string()).await?;

    add_dev_route(handle, iface, delegated, host).await?;
    Ok(())
}

async fn configure_loopback(handle: &Handle) -> Result<(), NetworkError> {
    const LOOPBACK_DEV: &str = "lo";
    const LOOPBACK_IPV6: &str = "::1";
    const LOOPBACK_IPV6_SUBNET: &str = "/128";

    trace!("configure {LOOPBACK_DEV}");
    add_address(
        handle,
        LOOPBACK_DEV.to_owned(),
        format!("{LOOPBACK_IPV6}{LOOPBACK_IPV6_SUBNET}")
            .parse::<Ipv6Net>()
            .expect("valid ipv6 address"),
    )
    .await?;
    set_link_up(handle, LOOPBACK_DEV.to_owned()).await?;
    info!("Successfully configured {}", LOOPBACK_DEV);
    Ok(())
}

/// Poll for a link with the given name. Returns once the link is found,
/// or [`NetworkError::TimedOutWaitingForLink`] after `timeout`.
async fn wait_for_link(
    handle: &Handle,
    iface: &str,
    timeout: Duration,
    poll_every: Duration,
) -> Result<(), NetworkError> {
    let start = Instant::now();
    loop {
        match get_link_index(handle, iface.to_string()).await {
            Ok(_) => return Ok(()),
            Err(NetworkError::DeviceNotFound { .. }) => {
                if start.elapsed() >= timeout {
                    return Err(NetworkError::TimedOutWaitingForLink {
                        iface: iface.to_string(),
                        timeout_ms: timeout.as_millis() as u64,
                    });
                }
                tokio::time::sleep(poll_every).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn add_address(
    handle: &Handle,
    iface: String,
    ip: impl Into<IpNet>,
) -> Result<(), NetworkError> {
    let ip = ip.into();
    let link_index = get_link_index(handle, iface.clone()).await?;
    handle
        .address()
        .add(link_index, ip.addr(), ip.prefix_len())
        .execute()
        .await
        .map(|_| trace!("Added address to link {iface}"))
        .or_else(|e| {
            // Address EEXIST really does mean "this exact address is
            // already on this link" (addresses are keyed per-interface),
            // unlike routes — tolerating it here is safe idempotency.
            if netlink_errno(&e) == Some(-libc::EEXIST) {
                warn!("Address {ip} already present on {iface}, ignoring");
                return Ok(());
            }
            Err(NetworkError::ErrorAddingAddress { iface, ip, source: e })
        })?;
    Ok(())
}

async fn set_link_up(
    handle: &Handle,
    iface: String,
) -> Result<(), NetworkError> {
    const TIMEOUT: Duration = Duration::from_secs(3);
    const POLL: Duration = Duration::from_millis(25);

    let link_index = get_link_index(handle, iface.clone()).await?;
    let msg = LinkUnspec::new_with_index(link_index).up().build();
    handle.link().set(msg).execute().await.map_err(|e| {
        NetworkError::ErrorSettingLinkUp { iface: iface.clone(), source: e }
    })?;

    // Poll for admin-up (IFF_UP), not carrier/oper-up: pair devices like
    // netkit only raise carrier once BOTH halves are up, and the host-side
    // primary legitimately comes up before the peer does inside the cell.
    // Admin-up is all the subsequent address/route adds need. No DAD wait
    // is needed either — netkit sets IFF_NOARP, so addresses skip the
    // tentative state. Timeout is warn-and-continue: the set request above
    // already succeeded, so a slow flag read shouldn't fail the caller.
    let start = Instant::now();
    loop {
        let link = handle
            .link()
            .get()
            .match_index(link_index)
            .execute()
            .try_next()
            .await;
        if let Ok(Some(link)) = link
            && link.header.flags.contains(LinkFlags::Up)
        {
            trace!("Link '{iface}' is up");
            return Ok(());
        }
        if start.elapsed() >= TIMEOUT {
            warn!(
                "Timed out after {}ms waiting for link '{iface}' to report \
                 IFF_UP; continuing anyway",
                TIMEOUT.as_millis()
            );
            return Ok(());
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Rename a link. Looks up the current link by name, then sends a
/// `RTM_SETLINK` with the new `IFLA_IFNAME` attribute. Idempotent on the
/// already-renamed case is NOT free — calling rename on a non-existent
/// link returns `DeviceNotFound`.
async fn rename_link(
    handle: &Handle,
    old: &str,
    new: &str,
) -> Result<(), NetworkError> {
    let idx = get_link_index(handle, old.to_string()).await?;
    let msg = LinkUnspec::new_with_index(idx).name(new.to_string()).build();
    handle.link().set(msg).execute().await.map_err(|e| {
        NetworkError::ErrorRenamingLink {
            old: old.to_string(),
            new: new.to_string(),
            source: e,
        }
    })?;
    trace!("Renamed link {old} → {new}");
    Ok(())
}

/// Extract the negative errno from a netlink NACK, if that's what the
/// error is. Lets call sites classify kernel responses (`-EEXIST`,
/// `-ENODEV`, ...) without pattern-matching boilerplate.
fn netlink_errno(err: &rtnetlink::Error) -> Option<i32> {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        msg.code.map(|c| c.get())
    } else {
        None
    }
}

/// True for names produced by [`Network::reserve_interface_names`] for
/// host-side primaries: `nk-` followed by exactly 8 hex chars. Used by
/// the leftover-state sweep to recognize this daemon's own devices.
fn is_cell_primary_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 11
        && bytes.starts_with(b"nk-")
        && bytes[3..].iter().all(|b| b.is_ascii_hexdigit())
}

async fn get_link_index(
    handle: &Handle,
    iface: String,
) -> Result<u32, NetworkError> {
    let link = handle
        .link()
        .get()
        .match_name(iface.clone())
        .execute()
        .try_next()
        .await;
    if let Ok(Some(link)) = link {
        Ok(link.header.index)
    } else {
        Err(NetworkError::DeviceNotFound { iface })
    }
}

/// Ensure a v6 host route: `dest dev iface src host_ip`. No gateway —
/// `dev` routes are sufficient for the routed point-to-link.
///
/// Sent with `NLM_F_REPLACE` ("ensure exactly this route"), NOT
/// `NLM_F_EXCL` + EEXIST-tolerance: EEXIST only means *a* route to the
/// prefix exists, not that it points at this device. A stale same-prefix
/// route via a dead device (leftover from a crashed daemon, or a
/// hard-kill racing re-allocation of the address) would otherwise be
/// silently kept and blackhole the new endpoint's return traffic.
async fn add_dev_route(
    handle: &Handle,
    iface: &str,
    dest: Ipv6Net,
    pref_source: Ipv6Addr,
) -> Result<(), NetworkError> {
    let link_index = get_link_index(handle, iface.to_string()).await?;
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dest.addr(), dest.prefix_len())
        .output_interface(link_index)
        .pref_source(pref_source)
        .build();
    handle.route().add(route).replace().execute().await.map_err(|e| {
        NetworkError::ErrorAddingRoute {
            iface: iface.to_string(),
            route_source: IpNet::V6(
                Ipv6Net::new(pref_source, 128).expect("/128"),
            ),
            route_destination: IpNet::V6(dest),
            source: e,
        }
    })?;
    Ok(())
}

/// Ensure an `onlink` default route: `default via <gw> dev iface onlink`.
/// `onlink` lets the kernel install the route even though the gateway
/// address is not in any directly-attached subnet (we use /128 on the
/// guest side, so the gateway lives outside the guest's "own" prefix).
///
/// Sent with `NLM_F_REPLACE` so a pre-existing default route (leftover
/// state) is superseded instead of failing the endpoint setup with
/// EEXIST.
async fn add_onlink_default(
    handle: &Handle,
    iface: &str,
    gateway: Ipv6Addr,
    pref_source: Ipv6Addr,
) -> Result<(), NetworkError> {
    let link_index = get_link_index(handle, iface.to_string()).await?;
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
        .output_interface(link_index)
        .gateway(gateway)
        .pref_source(pref_source)
        .onlink()
        .build();
    handle.route().add(route).replace().execute().await.map_err(|e| {
        NetworkError::ErrorAddingRoute {
            iface: iface.to_string(),
            route_source: IpNet::V6(
                Ipv6Net::new(pref_source, 128).expect("/128"),
            ),
            route_destination: IpNet::V6(
                "::/0".parse().expect("default route"),
            ),
            source: e,
        }
    })?;
    Ok(())
}

#[allow(clippy::result_large_err)]
fn enable_forwarding_v6() -> Result<(), NetworkError> {
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").map_err(
        |e| NetworkError::ErrorEnablingIpForwarding {
            family: "ipv6",
            msg: e.to_string(),
        },
    )?;
    trace!("Enabled IPv6 forwarding");
    Ok(())
}

/// Set `accept_ra=2` on the given interface so it keeps processing Router
/// Advertisements even when global IPv6 forwarding is on.
fn set_accept_ra_router_mode(iface: &str) -> std::io::Result<()> {
    let path = format!("/proc/sys/net/ipv6/conf/{iface}/accept_ra");
    std::fs::write(&path, b"2")?;
    trace!("Set accept_ra=2 on '{iface}'");
    Ok(())
}

async fn get_link_name(
    handle: &Handle,
    index: u32,
) -> Result<String, NetworkError> {
    let mut links = handle.link().get().match_index(index).execute();
    if let Some(link) = links.try_next().await? {
        for attr in link.attributes {
            if let LinkAttribute::IfName(name) = attr {
                return Ok(name);
            }
        }
    }
    Err(NetworkError::DeviceNotFound { iface: format!("index {}", index) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::route::RouteAddress;
    use rtnetlink::packet_core::ErrorMessage;
    use serial_test::serial;
    use std::num::NonZeroI32;
    use test_helpers::*;

    #[test]
    fn network_ready_allows_cells_only_for_full_or_local() {
        assert!(NetworkReady::Full.allows_cells());
        assert!(NetworkReady::LocalOnly.allows_cells());
        assert!(!NetworkReady::Unavailable.allows_cells());
    }

    #[test]
    fn cell_primary_name_matcher_is_strict() {
        assert!(is_cell_primary_name("nk-a1b2c3d4"));
        assert!(is_cell_primary_name("nk-00000000"));
        assert!(is_cell_primary_name("nk-DEADBEEF"));
        // Peers, wrong lengths, non-hex, other prefixes: never matched —
        // the leftover sweep must not take devices it doesn't own.
        assert!(!is_cell_primary_name("nk-a1b2c3d4-p"));
        assert!(!is_cell_primary_name("nk-a1b2c3d"));
        assert!(!is_cell_primary_name("nk-a1b2c3d4e"));
        assert!(!is_cell_primary_name("nk-a1b2c3dg"));
        assert!(!is_cell_primary_name("xk-a1b2c3d4"));
        assert!(!is_cell_primary_name("nk-"));
        assert!(!is_cell_primary_name("eth0"));
    }

    #[test]
    fn netlink_errno_classifies_only_nack_replies() {
        let mut nack = ErrorMessage::default();
        nack.code = NonZeroI32::new(-libc::ENODEV);
        assert_eq!(
            netlink_errno(&rtnetlink::Error::NetlinkError(nack)),
            Some(-libc::ENODEV)
        );

        // An ACK (code None) carries no errno.
        assert_eq!(
            netlink_errno(&rtnetlink::Error::NetlinkError(
                ErrorMessage::default()
            )),
            None
        );

        // Non-netlink error variants carry no errno either.
        assert_eq!(
            netlink_errno(&rtnetlink::Error::NamespaceError("x".into())),
            None
        );
    }

    // ---- Root-gated behavioral tests against a real kernel ----
    //
    // These mirror the cell.rs unit-test convention: they run only as
    // root (skipped otherwise) and operate on real netlink state, using
    // `tst-`-prefixed scratch devices and the fd00:dead:beef::/48 range
    // so they can't collide with live cell plumbing.

    async fn create_test_pair(handle: &Handle, primary: &str, peer: &str) {
        handle
            .link()
            .add(
                LinkNetkit::new(primary, peer, NetkitMode::L3)
                    .policy(NetkitPolicy::Pass)
                    .peer_policy(NetkitPolicy::Pass)
                    .build(),
            )
            .execute()
            .await
            .expect("create test netkit pair");
    }

    async fn delete_if_exists(handle: &Handle, name: &str) {
        if let Ok(idx) = get_link_index(handle, name.to_string()).await {
            let _ = handle.link().del(idx).execute().await;
        }
    }

    /// Find the oif of the v6 route to exactly `dest`, if any.
    async fn route_oif(handle: &Handle, dest: Ipv6Net) -> Option<u32> {
        let msg = RouteMessageBuilder::<Ipv6Addr>::new().build();
        let mut routes = handle.route().get(msg).execute();
        while let Ok(Some(route)) = routes.try_next().await {
            if route.header.destination_prefix_length != dest.prefix_len() {
                continue;
            }
            let mut matches_dest = false;
            let mut oif = None;
            for attr in &route.attributes {
                match attr {
                    RouteAttribute::Destination(RouteAddress::Inet6(a)) => {
                        matches_dest = *a == dest.addr();
                    }
                    RouteAttribute::Oif(i) => oif = Some(*i),
                    _ => {}
                }
            }
            if matches_dest {
                return oif;
            }
        }
        None
    }

    /// The kernel returns ENODEV when deleting a link that disappeared
    /// between lookup and delete (pair devices race netns teardown) —
    /// the exact classification the tolerant delete paths rely on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // Serialized: mutates global host netlink state.
    #[serial]
    async fn delete_tolerates_already_gone_device() {
        skip_if_not_root!("delete_tolerates_already_gone_device");
        skip_if_seccomp!("delete_tolerates_already_gone_device");

        let network = Network::connect().expect("netlink connect");
        let handle = &network.handle;
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

    /// `add_dev_route` must supersede a stale same-prefix route that
    /// points at a different device (leftover from a crashed daemon or a
    /// hard-kill race) instead of silently keeping it: with NLM_F_EXCL
    /// the second add would EEXIST and the stale route would keep
    /// blackholing the new endpoint's return traffic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // Serialized: mutates global host netlink state.
    #[serial]
    async fn dev_route_replace_supersedes_stale_route() {
        skip_if_not_root!("dev_route_replace_supersedes_stale_route");
        skip_if_seccomp!("dev_route_replace_supersedes_stale_route");

        let network = Network::connect().expect("netlink connect");
        let handle = &network.handle;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let stale = format!("tst-{}", &suffix[..8]);
        let stale_peer = format!("{stale}-p");
        let fresh = format!("tsu-{}", &suffix[..8]);
        let fresh_peer = format!("{fresh}-p");
        let host: Ipv6Addr = "fd00:dead:beef::1".parse().expect("addr");
        let dest: Ipv6Net = "fd00:dead:beef::2/128".parse().expect("net");

        create_test_pair(handle, &stale, &stale_peer).await;
        create_test_pair(handle, &fresh, &fresh_peer).await;

        let setup: Result<(), NetworkError> = async {
            add_address(
                handle,
                stale.clone(),
                Ipv6Net::new(host, 128).expect("/128"),
            )
            .await?;
            set_link_up(handle, stale.clone()).await?;
            set_link_up(handle, fresh.clone()).await?;
            // The "leftover" route via the stale device...
            add_dev_route(handle, &stale, dest, host).await?;
            // ...must be atomically superseded by the new endpoint's.
            add_dev_route(handle, &fresh, dest, host).await?;
            Ok(())
        }
        .await;

        let oif = route_oif(handle, dest).await;
        let fresh_idx = get_link_index(handle, fresh.clone()).await.ok();

        // Clean up before asserting so failures don't leak devices (the
        // routes die with the links).
        delete_if_exists(handle, &stale).await;
        delete_if_exists(handle, &fresh).await;

        setup.expect("route setup");
        assert_eq!(
            oif, fresh_idx,
            "the route must point at the replacing device, not the stale one"
        );
    }

    /// The startup sweep must reclaim leftover `nk-<hex>` netkit
    /// primaries (a previous daemon's cell plumbing) and must NOT touch
    /// netkit devices outside that namespace.
    ///
    /// NOTE: like the daemon's own startup, this deletes any live
    /// `nk-<8 hex>` netkit devices on the host — don't run root tests
    /// next to a production auraed (the existing nft-table tests have
    /// the same single-daemon assumption).
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // Serialized: mutates global host netlink state.
    #[serial]
    async fn leftover_sweep_removes_only_cell_primaries() {
        skip_if_not_root!("leftover_sweep_removes_only_cell_primaries");
        skip_if_seccomp!("leftover_sweep_removes_only_cell_primaries");

        let network = Network::connect().expect("netlink connect");
        let handle = &network.handle;
        let (cell_like, cell_like_peer) = network.reserve_interface_names();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let bystander = format!("tst-{}", &suffix[..8]);
        let bystander_peer = format!("{bystander}-p");

        create_test_pair(handle, &cell_like, &cell_like_peer).await;
        create_test_pair(handle, &bystander, &bystander_peer).await;

        network.cleanup_leftover_cell_interfaces().await;

        let cell_like_gone =
            get_link_index(handle, cell_like.clone()).await.is_err();
        let bystander_kept =
            get_link_index(handle, bystander.clone()).await.is_ok();

        delete_if_exists(handle, &cell_like).await;
        delete_if_exists(handle, &bystander).await;

        assert!(
            cell_like_gone,
            "sweep must remove leftover nk-<hex> netkit primaries"
        );
        assert!(
            bystander_kept,
            "sweep must not touch netkit devices it doesn't own"
        );
    }
}
