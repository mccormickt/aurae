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
use netlink_packet_route::link::{LinkAttribute, NetkitMode, NetkitPolicy};
use netlink_packet_route::route::RouteAttribute;
use nix::libc::EEXIST;
use rtnetlink::{Handle, LinkNetkit, LinkUnspec, RouteMessageBuilder};
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::os::fd::RawFd;
use std::str;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{error, info, trace, warn};

use crate::cells::cell_service::cells::CellName;
use crate::init::network::endpoint::NetworkConfig;
use crate::init::network::ipam::{Allocation, Ipam, IpamConfig};

pub(crate) mod endpoint;
pub(crate) mod ipam;
pub(crate) mod nat;
mod sriov;

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
    #[error(transparent)]
    Other(#[from] rtnetlink::Error),
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
    /// Per-cell host-side interface primary names (e.g. `nk-a1b2c3d4`),
    /// keyed by cell name. The peer in the cell's netns disappears with
    /// the netns; we only need to track the host-side primary for
    /// teardown.
    cell_interfaces: Mutex<HashMap<CellName, String>>,
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
    /// 1. Build the interface pair (netkit in L2 mode with the `Pass`
    ///    policy on both ends so packets flow without an L2 segment).
    /// 2. Move the peer into `peer_netns_fd`.
    /// 3. Configure the host-side primary with `host_ip/128` and bring
    ///    it up.
    /// 4. Add a `dev` route for the delegated guest prefix via the primary
    ///    so return traffic from the cell reaches the host stack.
    /// 5. Track the primary in `cell_interfaces` so
    ///    `destroy_cell_interface` can find it later.
    ///
    /// On failure of any step after step 1, the primary is deleted so the
    /// pair doesn't leak. The kernel removes the orphaned peer along with
    /// its primary.
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
                LinkNetkit::new(primary, peer, NetkitMode::L2)
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

        // 2. Move the peer into the cell's netns. The peer name is
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

            // 3 & 4: configure the routed host endpoint.
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
            // Roll back: delete the primary. The kernel removes the peer
            // along with it (whether still local or already in the cell
            // netns — orphaned interface halves are reaped).
            self.delete_primary_best_effort(primary).await;
            return Err(e);
        }

        // 5. Track the host-side primary so destroy_cell_interface can find
        //    it. If the mutex is poisoned the daemon is in an unrecoverable
        //    state — bail and roll back rather than leak.
        let track_result = match self.cell_interfaces.lock() {
            Ok(mut guard) => {
                let _ = guard.insert(cell_name.clone(), primary.to_string());
                Ok(())
            }
            Err(_poisoned) => Err(NetworkError::CellInterfacesPoisoned),
        };

        if let Err(e) = track_result {
            error!(
                "cell_interfaces mutex poisoned — rolling back interface `{primary}`"
            );
            self.delete_primary_best_effort(primary).await;
            return Err(e);
        }

        info!(
            "Created cell interface for {cell_name}: primary={primary} \
             peer={peer}, host={}, guest={}",
            allocation.host_ip, allocation.guest_ip,
        );
        Ok(())
    }

    /// Best-effort delete of a host-side interface primary by name. Used
    /// from `create_cell_interface`'s rollback path. Errors are logged
    /// rather than propagated — the caller is already returning an
    /// error and would lose the original cause if we replaced it.
    async fn delete_primary_best_effort(&self, primary: &str) {
        match get_link_index(&self.handle, primary.to_string()).await {
            Ok(idx) => {
                if let Err(e) = self.handle.link().del(idx).execute().await {
                    warn!(
                        "Rollback: failed to delete primary `{primary}` \
                         (index {idx}): {e}. Host interface may leak."
                    );
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

    /// Tear down the host-side interface primary for a cell. The peer
    /// disappears with the cell's netns (kernel removes orphaned
    /// interface halves), and the kernel removes routes referring to a
    /// deleted link automatically — so this only needs to delete the
    /// primary.
    pub(crate) async fn destroy_cell_interface(
        &self,
        cell_name: &CellName,
    ) -> Result<(), NetworkError> {
        let entry = match self.cell_interfaces.lock() {
            Ok(mut guard) => guard.remove(cell_name),
            Err(_poisoned) => {
                error!(
                    "cell_interfaces mutex poisoned — cannot remove entry for \
                     {cell_name}. Host-side primary will leak."
                );
                return Ok(());
            }
        };

        let Some(primary) = entry else {
            // No-op: cell had no interface (e.g. isolate_network=false, or
            // create_cell_interface failed before insert).
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

        self.handle.link().del(index).execute().await.map_err(|e| {
            NetworkError::ErrorDeletingLink {
                iface: primary.clone(),
                index,
                source: e,
            }
        })?;
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
            if let rtnetlink::Error::NetlinkError(msg) = &e {
                let dup_code: i32 = -EEXIST;
                if msg
                    .code
                    .map(|c| c.get())
                    .map(|c| c == dup_code)
                    .unwrap_or(false)
                {
                    warn!("Address {ip} already present on {iface}, ignoring");
                    return Ok(());
                }
            }
            Err(NetworkError::ErrorAddingAddress { iface, ip, source: e })
        })?;
    Ok(())
}

async fn set_link_up(
    handle: &Handle,
    iface: String,
) -> Result<(), NetworkError> {
    let link_index = get_link_index(handle, iface.clone()).await?;
    let msg = LinkUnspec::new_with_index(link_index).up().build();
    handle.link().set(msg).execute().await.map_err(|e| {
        NetworkError::ErrorSettingLinkUp { iface: iface.clone(), source: e }
    })?;
    // TODO: replace sleep with an await mechanism that checks if device is
    // up (with a timeout). https://github.com/aurae-runtime/auraed/issues/40
    info!("Waiting for link '{iface}' to become up");
    tokio::time::sleep(Duration::from_secs(3)).await;
    info!("Waited 3 seconds, assuming link '{iface}' is up");
    Ok(())
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

/// Install a v6 host route: `dest dev iface src host_ip`. No gateway —
/// `dev` routes are sufficient for the routed point-to-link.
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
    handle.route().add(route).execute().await.or_else(|e| {
        if let rtnetlink::Error::NetlinkError(msg) = &e
            && msg.code.map(|c| c.get()) == Some(-EEXIST)
        {
            return Ok(());
        }
        Err(NetworkError::ErrorAddingRoute {
            iface: iface.to_string(),
            route_source: IpNet::V6(
                Ipv6Net::new(pref_source, 128).expect("/128"),
            ),
            route_destination: IpNet::V6(dest),
            source: e,
        })
    })?;
    Ok(())
}

/// Install an `onlink` default route: `default via <gw> dev iface onlink`.
/// `onlink` lets the kernel install the route even though the gateway
/// address is not in any directly-attached subnet (we use /128 on the
/// guest side, so the gateway lives outside the guest's "own" prefix).
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
    handle.route().add(route).execute().await.map_err(|e| {
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

    #[test]
    fn network_ready_allows_cells_only_for_full_or_local() {
        assert!(NetworkReady::Full.allows_cells());
        assert!(NetworkReady::LocalOnly.allows_cells());
        assert!(!NetworkReady::Unavailable.allows_cells());
    }
}
