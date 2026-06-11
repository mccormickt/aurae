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

//! Cell and endpoint networking.
//!
//! The parts, outermost first:
//!   * [`Network`] gives the daemon or a nested auraed access to netlink,
//!     the nft table, and the IPAM allocator. [`Network::connect`] builds
//!     it.
//!   * [`host`] does the host-side init: forwarding, the nft ruleset, and
//!     the reconciliation of leftover interfaces. It runs in the daemon
//!     only.
//!   * [`cell`] does the per-cell interface lifecycle.
//!   * [`netlink`] has the stateless link, address, and route helpers.
//!   * [`nat`] is the enforcement layer.
//!   * [`ipam`] and [`endpoint`] do the address allocation and hold the
//!     configuration that a nested auraed applies to itself.
//!
//! `init_endpoint` is in this module and not in [`cell`], because it runs
//! in the network namespace of the endpoint. A cell or a VM configures itself with it.

use ipnet::Ipv6Net;
use rtnetlink::Handle;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

use crate::cells::cell_service::cells::CellName;
use crate::init::network::endpoint::NetworkConfig;
use crate::init::network::ipam::{Ipam, IpamConfig};

mod cell;
pub(crate) mod endpoint;
mod host;
pub(crate) mod ipam;
pub(crate) mod nat;
mod netlink;
mod sriov;

use cell::CellInterfaceState;
use host::enable_forwarding_v6;
use nat::NatManager;
use netlink::{
    add_address, add_onlink_default, configure_loopback,
    configure_routed_endpoint, rename_link, set_link_up, wait_for_link,
};

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Failed to initialize network: {0}")]
    FailedToConnect(#[from] std::io::Error),
    #[error("Could not find link `{iface}`")]
    DeviceNotFound { iface: String },
    #[error("Error adding address `{ip}` to link `{iface}`: {source}")]
    ErrorAddingAddress { iface: String, ip: Ipv6Net, source: rtnetlink::Error },
    #[error("Failed to set link up for device `{iface}`: {source}")]
    ErrorSettingLinkUp { iface: String, source: rtnetlink::Error },
    #[error("Error adding route to `{route}` for device `{iface}`: {source}")]
    ErrorAddingRoute { iface: String, route: Ipv6Net, source: rtnetlink::Error },
    #[error("Failed to enable IP forwarding ({family}): {msg}")]
    ErrorEnablingIpForwarding { family: &'static str, msg: String },
    #[error(
        "Failed to configure the host network during {operation}: {source}"
    )]
    ErrorConfiguringHost {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
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

/// A cloneable handle to the network state of the host.
///
/// The shared state contains netlink, nftables, interface, and IPAM state.
/// The last handle removes the nftables table.
#[derive(Clone)]
pub(crate) struct Network {
    inner: Arc<NetworkInner>,
}

struct NetworkInner {
    handle: Handle,
    /// The nftables state and its lifecycle.
    nat: NatManager,
    /// The host interface state for each cell.
    cell_interfaces: Mutex<HashMap<CellName, CellInterfaceState>>,
    /// The IPAM allocator.
    ipam: Ipam,
}

impl fmt::Debug for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Handle` does not implement `Debug`. Report the nat state.
        let cell_count =
            self.inner.cell_interfaces.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("Network")
            .field("nat_installed", &self.inner.nat.is_installed())
            .field("cell_interface_count", &cell_count)
            .finish()
    }
}

/// Builder for [`Network`]. It holds the configuration that the `Network`
/// needs before the connection: the IPAM pool, and the request to enable
/// IPv6 forwarding in the netns. Thus a `Network` starts with the correct
/// state, and no caller reconfigures a default afterwards. [`Self::build`]
/// opens the netlink connection and applies the forwarding sysctl in the
/// netns of the caller. For a nested auraed that netns is the netns of its
/// cell.
#[derive(Default)]
pub(crate) struct NetworkBuilder {
    ipam: IpamConfig,
    enable_forwarding: bool,
}

impl NetworkBuilder {
    /// Set the pool and the device prefix that the allocator gives out
    /// from. The host daemon uses the pool of the daemon. A nested auraed
    /// uses the block that its cell received. Refer to
    /// [`NetworkConfig::nested_ipam_config`](super::endpoint::NetworkConfig::nested_ipam_config).
    pub(crate) fn ipam(mut self, config: IpamConfig) -> Self {
        self.ipam = config;
        self
    }

    /// Enable IPv6 forwarding in the netns where [`Self::build`] runs. A
    /// nested auraed needs it to route between the TAP of each VM and
    /// `eth0`. The host daemon enables forwarding in
    /// [`Network::init_host_network`], together with the NAT rules, the
    /// guard, and the WAN setup.
    pub(crate) fn enable_forwarding(mut self) -> Self {
        self.enable_forwarding = true;
        self
    }

    /// Open the netlink connection, apply the forwarding sysctl if the
    /// caller requested it, and build the `Network` with the given IPAM.
    pub(crate) fn build(self) -> Result<Network, NetworkError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        let _ignored = tokio::spawn(connection);
        if self.enable_forwarding {
            enable_forwarding_v6()?;
        }
        Ok(Network {
            inner: Arc::new(NetworkInner {
                handle,
                nat: NatManager::new(),
                cell_interfaces: Mutex::new(HashMap::new()),
                ipam: Ipam::new(self.ipam),
            }),
        })
    }
}

impl Network {
    /// Open a netlink connection and build a `Network` with the given IPAM
    /// and no forwarding. This is the short form of
    /// `Network::builder().ipam(config).build()`.
    pub(crate) fn connect(
        ipam_config: IpamConfig,
    ) -> Result<Network, NetworkError> {
        Self::builder().ipam(ipam_config).build()
    }

    /// Start building a `Network`. See [`NetworkBuilder`].
    pub(crate) fn builder() -> NetworkBuilder {
        NetworkBuilder::default()
    }

    pub(crate) fn ipam(&self) -> &Ipam {
        &self.inner.ipam
    }

    /// Reserve a unique TAP name for a VM. Cloud Hypervisor creates the
    /// device with this name at the boot of the VM.
    /// [`Self::configure_tap_endpoint`] then configures the host side. The
    /// prefix `vm-` separates a VM tap from a cell netkit interface, which
    /// uses the prefix `nk-`. The name is shorter than IFNAMSIZ (16).
    pub(crate) fn reserve_tap_name(&self) -> String {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        format!("vm-{}", &suffix[..8])
    }

    /// Configure the host side of the routed TAP of a VM after Cloud
    /// Hypervisor creates it. The function adds `host/128`, sets the link
    /// up, and installs a `dev` route for the delegated prefix of the VM,
    /// so that return traffic reaches the host stack. This is the same
    /// host-side step as in [`Self::create_cell_interface`], but Cloud
    /// Hypervisor owns the TAP and this function only adds the addressing.
    /// It waits a maximum of 5 s for the TAP, because Cloud Hypervisor
    /// creates the device during the boot of the VM.
    pub(crate) async fn configure_tap_endpoint(
        &self,
        tap: &str,
        host: Ipv6Addr,
        delegated: Ipv6Net,
    ) -> Result<(), NetworkError> {
        const TIMEOUT: Duration = Duration::from_secs(5);
        const POLL: Duration = Duration::from_millis(50);
        let _ = wait_for_link(&self.inner.handle, tap, TIMEOUT, POLL).await?;
        configure_routed_endpoint(&self.inner.handle, tap, host, delegated)
            .await?;
        info!(
            "Configured VM TAP endpoint {tap}: host={host}, guest={delegated}"
        );
        Ok(())
    }

    /// Set up the local NIC of an auraed that runs in its own network namespace. The
    /// cell runtime and the pid1 VM runtime both use this function.
    /// The shared netlink handle is bound to the network namespace of the caller.
    ///
    /// Steps:
    /// 1. Set the loopback up. A new network namespace has `lo` down, and an
    ///    application that binds to localhost then fails.
    /// 2. Wait a maximum of 5 s for a link with the name
    ///    `config.interface_name`. The parent gives a cell a unique name
    ///    `nk-<hex>-p` and moves that link into this network namespace. A VM usually
    ///    has `eth0` immediately. A poll loop is sufficient, because
    ///    rtnetlink calls complete in milliseconds. If the poll becomes
    ///    unreliable, use RTNLGRP_LINK notifications.
    /// 3. Rename `interface_name` to `eth0`. The unique outer name
    ///    prevented a conflict with the `eth0` of the host. In this network namespace
    ///    the name `eth0` is free, and it is the usual name of the primary
    ///    NIC. The step does nothing if the name is already `eth0`, which
    ///    is the usual condition for a VM.
    /// 4. Set `eth0` up.
    /// 5. Add `guest_v6/<prefix>` to `eth0`.
    /// 6. Add an `onlink` default route through the host gateway. The
    ///    `onlink` flag is necessary, because the gateway address is
    ///    outside the prefix of the endpoint.
    ///
    /// A cell endpoint is a netkit peer in L3 mode. It has `ARPHRD_NONE`
    /// and `IFF_NOARP`, no MAC address, and no link-local address. The
    /// `via` gateway still operates, because a neighbour on a NOARP device
    /// is `NUD_NOARP`. The kernel does not resolve a link-layer address and
    /// sends the packets directly to the device.
    pub(crate) async fn init_endpoint(
        &self,
        config: &NetworkConfig,
    ) -> Result<(), NetworkError> {
        const ETH0: &str = "eth0";
        const TIMEOUT: Duration = Duration::from_secs(5);
        const POLL: Duration = Duration::from_millis(50);

        configure_loopback(&self.inner.handle).await?;

        // Resolve the NIC one time and use its index below. A rename does
        // not change the ifindex. The index stays valid.
        let link_index = wait_for_link(
            &self.inner.handle,
            &config.interface_name,
            TIMEOUT,
            POLL,
        )
        .await?;
        if config.interface_name != ETH0 {
            rename_link(
                &self.inner.handle,
                link_index,
                &config.interface_name,
                ETH0,
            )
            .await?;
        }

        set_link_up(&self.inner.handle, link_index, ETH0).await?;

        // Bind only the address of this endpoint at /128, never the full
        // delegated block. `delegated_prefix_len_v6` is the width of the
        // block that the host gave to this endpoint. A route realizes that
        // block: the host routes it to the primary, and a VM-hosting cell
        // sub-delegates a /128 from it to each TAP with its own dev route.
        // The block is not on-link on `eth0`. An on-link block would
        // conflict with those more specific TAP routes, and it would
        // discard the traffic to an address in the block that no VM uses.
        // A /128 keeps `eth0` at the one identity address of the endpoint.
        // The `onlink` default route still reaches the gateway, which is
        // outside that /128.
        let addr = Ipv6Net::new(config.guest_v6, 128).map_err(|e| {
            NetworkError::Other(rtnetlink::Error::NamespaceError(e.to_string()))
        })?;
        add_address(&self.inner.handle, link_index, ETH0, addr).await?;

        add_onlink_default(
            &self.inner.handle,
            link_index,
            ETH0,
            config.host_v6,
            config.guest_v6,
        )
        .await?;

        info!(
            "Configured endpoint (source={}→{ETH0}): \
             guest={}/128 (delegated /{}), default via {}",
            config.interface_name,
            config.guest_v6,
            config.delegated_prefix_len_v6,
            config.host_v6,
        );
        Ok(())
    }
}

impl Drop for NetworkInner {
    /// Remove the nftables state when the last handle is dropped.
    fn drop(&mut self) {
        if let Err(e) = self.nat.uninstall() {
            warn!("Failed to uninstall NAT ruleset: {e}");
        }
    }
}

/// Helpers for the root-only tests in the child modules. They change real
/// netlink state. They use device names with the prefix `tst-` and
/// addresses from fd00:dead:beef::/48. Thus they cannot interfere with the
/// interfaces of a live cell.
#[cfg(test)]
pub(crate) mod testutil {
    use super::netlink::get_link_index;
    use super::{Handle, Ipv6Net};
    use futures::stream::TryStreamExt;
    use netlink_packet_route::link::{NetkitMode, NetkitPolicy};
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};
    use rtnetlink::{LinkNetkit, RouteMessageBuilder};
    use std::net::Ipv6Addr;

    pub(crate) async fn create_test_pair(
        handle: &Handle,
        primary: &str,
        peer: &str,
    ) {
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

    pub(crate) async fn delete_if_exists(handle: &Handle, name: &str) {
        if let Ok(idx) = get_link_index(handle, name.to_string()).await {
            let _ = handle.link().del(idx).execute().await;
        }
    }

    /// Find the oif of the v6 route to `dest`, if such a route exists.
    pub(crate) async fn route_oif(
        handle: &Handle,
        dest: Ipv6Net,
    ) -> Option<u32> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nft ruleset must use the same prefix as the allocator. If the
    /// two prefixes differ, each cell loses its egress, and the anti-spoof
    /// rule drops all of its traffic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn ipam_pool_is_the_single_source_of_truth_for_the_pool() {
        let pool: Ipv6Net = "fd00:beef::/48".parse().expect("valid pool");
        let network =
            Network::connect(IpamConfig::new(pool, 128).expect("valid config"))
                .expect("netlink connect");

        assert_eq!(
            network.ipam().pool(),
            pool,
            "connect() must seed the allocator from the config that \
             init_host_network reads back when building the nft rules"
        );
        let alloc = network.ipam().allocate("cell:test").expect("allocate");
        assert!(
            network.ipam().pool().contains(&alloc.guest_ip),
            "allocator handed out an address outside the pool the nft \
             rules are built from"
        );
    }
}
