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

//! Host-side network initialization. It sets the forwarding sysctls,
//! installs the `inet aurae` nft table, and reconciles the leftover state
//! of a previous daemon.
//!
//! Only the daemon runs these functions. A nested auraed builds a `Network`
//! and calls `init_endpoint` to configure its own endpoint.

use super::netlink::{get_link_name, netlink_errno};
use super::{Network, NetworkError};
use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo};
use netlink_packet_route::route::RouteAttribute;
use nix::libc;
use rtnetlink::RouteMessageBuilder;
use std::net::Ipv6Addr;
use tracing::{error, info, trace, warn};

impl Network {
    /// Prepare the host network for cells.
    ///
    /// This function removes stale cell links. It then installs the nftables
    /// rules. It enables IPv6 forwarding as the last step.
    ///
    /// A host without an IPv6 default route has no cell egress. This
    /// condition does not stop local cell traffic.
    pub(crate) async fn init_host_network(&self) -> Result<(), NetworkError> {
        let pool_v6 = self.inner.ipam.pool();

        // Find the WAN before forwarding changes Router Advertisement rules.
        let wan_iface = self.get_default_route_iface().await?;

        // Remove all stale links before IPAM can reuse an address.
        self.cleanup_leftover_cell_interfaces().await?;

        if let Some(wan_iface) = wan_iface.as_deref() {
            set_accept_ra_router_mode(wan_iface).map_err(|source| {
                NetworkError::ErrorConfiguringHost {
                    operation: "the accept_ra update",
                    source,
                }
            })?;
        }

        // Install packet filtering before the host forwards a cell packet.
        self.inner.nat.install(pool_v6, wan_iface.as_deref()).map_err(|e| {
            error!(
                "Failed to install nft ruleset for v6={pool_v6}: {e}. \
                 Refusing to start cells without per-cell anti-spoof."
            );
            NetworkError::FailedToConnect(e)
        })?;

        if let Err(e) = enable_forwarding_v6() {
            if let Err(cleanup_error) = self.inner.nat.uninstall() {
                warn!(
                    "Failed to remove nft rules after forwarding failed: \
                     {cleanup_error}"
                );
            }
            return Err(e);
        }

        match wan_iface {
            Some(wan) => info!(
                "Host network ready for v6={pool_v6}: per-cell anti-spoof, \
                 cell-to-cell, and NAT egress via '{wan}'"
            ),
            None => warn!(
                "Host network ready for v6={pool_v6}, but there is no IPv6 \
                 default route — cells reach each other and the host, not \
                 the internet."
            ),
        }
        Ok(())
    }

    /// Remove cell links from an earlier daemon process.
    ///
    /// The function returns an error if it cannot confirm the cleanup.
    async fn cleanup_leftover_cell_interfaces(
        &self,
    ) -> Result<(), NetworkError> {
        let mut links = self.inner.handle.link().get().execute();
        let mut leftovers: Vec<(u32, String)> = Vec::new();
        while let Some(link) = links.try_next().await? {
            let mut name = None;
            let mut is_netkit = false;
            for attr in &link.attributes {
                match attr {
                    LinkAttribute::IfName(n) => name = Some(n.clone()),
                    LinkAttribute::LinkInfo(infos) => {
                        is_netkit = infos.iter().any(|info| {
                            matches!(info, LinkInfo::Kind(InfoKind::Netkit))
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

        for (index, name) in leftovers {
            match self.inner.handle.link().del(index).execute().await {
                Ok(()) => {
                    info!(
                        "Reclaimed leftover cell primary `{name}` \
                         (index {index}) from a previous daemon"
                    );
                }
                Err(e) if netlink_errno(&e) == Some(-libc::ENODEV) => {}
                Err(source) => {
                    return Err(NetworkError::ErrorDeletingLink {
                        iface: name,
                        index,
                        source,
                    });
                }
            }
        }
        Ok(())
    }

    /// Get the interface name of the default route. The function examines
    /// the IPv6 routes only, because cell networking is IPv6-only.
    async fn get_default_route_iface(
        &self,
    ) -> Result<Option<String>, NetworkError> {
        let route_msg = RouteMessageBuilder::<Ipv6Addr>::new().build();
        let mut routes = self.inner.handle.route().get(route_msg).execute();
        while let Some(route) = routes.try_next().await? {
            if route.header.destination_prefix_length == 0
                && route.header.address_family == AddressFamily::Inet6
            {
                for attr in &route.attributes {
                    if let RouteAttribute::Oif(oif_index) = attr {
                        let name =
                            get_link_name(&self.inner.handle, *oif_index)
                                .await?;
                        if !name.is_empty() {
                            return Ok(Some(name));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

/// True for a host-side primary name from
/// [`Network::reserve_interface_names`]: `nk-` and 8 hexadecimal
/// characters. The leftover sweep uses it to find its own devices.
pub(super) fn is_cell_primary_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 11
        && bytes.starts_with(b"nk-")
        && bytes[3..].iter().all(|b| b.is_ascii_hexdigit())
}

pub(super) fn enable_forwarding_v6() -> Result<(), NetworkError> {
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").map_err(
        |e| NetworkError::ErrorEnablingIpForwarding {
            family: "ipv6",
            msg: e.to_string(),
        },
    )?;
    trace!("Enabled IPv6 forwarding");
    Ok(())
}

/// Set `accept_ra=2` on the interface. The interface then continues to
/// process Router Advertisements while global IPv6 forwarding is on.
fn set_accept_ra_router_mode(iface: &str) -> std::io::Result<()> {
    let path = format!("/proc/sys/net/ipv6/conf/{iface}/accept_ra");
    std::fs::write(&path, b"2")?;
    trace!("Set accept_ra=2 on '{iface}'");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::netlink::get_link_index;
    use super::super::testutil::*;
    use super::super::{Network, ipam::IpamConfig};
    use super::*;
    use serial_test::serial;
    use test_helpers::*;

    #[test]
    fn cell_primary_name_matcher_is_strict() {
        assert!(is_cell_primary_name("nk-a1b2c3d4"));
        assert!(is_cell_primary_name("nk-00000000"));
        assert!(is_cell_primary_name("nk-DEADBEEF"));
        // A peer name, an incorrect length, a non-hexadecimal character,
        // or a different prefix must not match. The leftover sweep must
        // not delete a device of a different owner.
        assert!(!is_cell_primary_name("nk-a1b2c3d4-p"));
        assert!(!is_cell_primary_name("nk-a1b2c3d"));
        assert!(!is_cell_primary_name("nk-a1b2c3d4e"));
        assert!(!is_cell_primary_name("nk-a1b2c3dg"));
        assert!(!is_cell_primary_name("xk-a1b2c3d4"));
        assert!(!is_cell_primary_name("nk-"));
        assert!(!is_cell_primary_name("eth0"));
    }

    /// The startup sweep must delete the leftover `nk-<hex>` netkit
    /// primaries of a previous daemon. It must not delete a netkit device
    /// outside that namespace.
    ///
    /// This test deletes each live `nk-<8 hex>` netkit device on the host,
    /// as the startup of the daemon does. Do not run the root tests on a
    /// host with a production auraed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // This test changes global host netlink state.
    #[serial]
    async fn leftover_sweep_removes_only_cell_primaries() {
        skip_if_not_root!("leftover_sweep_removes_only_cell_primaries");
        skip_if_seccomp!("leftover_sweep_removes_only_cell_primaries");

        let network =
            Network::connect(IpamConfig::default()).expect("netlink connect");
        let handle = &network.inner.handle;
        let (cell_like, cell_like_peer) = network.reserve_interface_names();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let bystander = format!("tst-{}", &suffix[..8]);
        let bystander_peer = format!("{bystander}-p");

        create_test_pair(handle, &cell_like, &cell_like_peer).await;
        create_test_pair(handle, &bystander, &bystander_peer).await;

        network.cleanup_leftover_cell_interfaces().await.expect("cleanup");

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
