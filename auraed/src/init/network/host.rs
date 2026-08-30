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
use super::{CELL_INTERFACE_ALIAS, Network, NetworkError};
use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo};
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use nix::libc;
use rtnetlink::RouteMessageBuilder;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use tracing::{error, info, trace, warn};

const FORWARDING_V6_PATH: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

#[derive(Debug)]
pub(super) struct HostSysctlState {
    forwarding_original: String,
    accept_ra: Option<(PathBuf, String)>,
}

impl HostSysctlState {
    fn capture(wan_iface: Option<&str>) -> std::io::Result<Self> {
        let forwarding_original = std::fs::read_to_string(FORWARDING_V6_PATH)?;
        let accept_ra = wan_iface
            .map(|iface| {
                let path = PathBuf::from(format!(
                    "/proc/sys/net/ipv6/conf/{iface}/accept_ra"
                ));
                let original = std::fs::read_to_string(&path)?;
                Ok::<_, std::io::Error>((path, original))
            })
            .transpose()?;
        Ok(Self { forwarding_original, accept_ra })
    }

    fn enable_accept_ra(&self) -> std::io::Result<()> {
        if let Some((path, _)) = &self.accept_ra {
            std::fs::write(path, b"2")?;
            trace!("Set accept_ra=2 on '{}'", path.display());
        }
        Ok(())
    }

    fn enable_forwarding(&self) -> std::io::Result<()> {
        std::fs::write(FORWARDING_V6_PATH, b"1")?;
        trace!("Enabled IPv6 forwarding");
        Ok(())
    }

    pub(super) fn restore(self) -> std::io::Result<()> {
        let forwarding =
            std::fs::write(FORWARDING_V6_PATH, self.forwarding_original);
        let accept_ra = self
            .accept_ra
            .map_or(Ok(()), |(path, original)| std::fs::write(path, original));
        forwarding.and(accept_ra)
    }
}

impl Network {
    /// Prepare the host network for cells.
    ///
    /// This function removes stale cell links. It then installs the nftables
    /// rules. It enables IPv6 forwarding as the last step.
    ///
    /// A host without an IPv6 default route has no cell egress. Host and
    /// sibling isolation remain installed.
    pub(crate) async fn init_host_network(&self) -> Result<(), NetworkError> {
        let pool_v6 = self.inner.ipam.pool();

        // Find the WAN before forwarding changes Router Advertisement rules.
        let wan_iface = self.get_default_route_iface().await?;

        // Remove all stale links before IPAM can reuse an address.
        self.cleanup_leftover_cell_interfaces().await?;
        self.ensure_pool_does_not_overlap_routes(pool_v6).await?;

        let sysctls = HostSysctlState::capture(wan_iface.as_deref()).map_err(
            |source| NetworkError::ErrorConfiguringHost {
                operation: "capture of existing sysctls",
                source,
            },
        )?;
        if let Err(source) = sysctls.enable_accept_ra() {
            let error = NetworkError::ErrorConfiguringHost {
                operation: "the accept_ra update",
                source,
            };
            if let Err(restore_error) = sysctls.restore() {
                warn!(
                    "Failed to restore sysctls after accept_ra error: \
                     {restore_error}"
                );
            }
            return Err(error);
        }

        // Install packet filtering before the host forwards a cell packet.
        if let Err(e) = self.inner.nat.install(pool_v6, wan_iface.as_deref()) {
            error!(
                "Failed to install nft ruleset for v6={pool_v6}: {e}. \
                 Refusing to start cells without per-cell anti-spoof."
            );
            if let Err(restore_error) = sysctls.restore() {
                warn!(
                    "Failed to restore sysctls after nft error: {restore_error}"
                );
            }
            return Err(NetworkError::FailedToConnect(e));
        }

        if let Err(source) = sysctls.enable_forwarding() {
            if let Err(cleanup_error) = self.inner.nat.uninstall() {
                warn!(
                    "Failed to remove nft rules after forwarding failed: \
                     {cleanup_error}"
                );
            }
            if let Err(restore_error) = sysctls.restore() {
                warn!(
                    "Failed to restore sysctls after forwarding error: \
                     {restore_error}"
                );
            }
            return Err(NetworkError::ErrorEnablingIpForwarding {
                family: "ipv6",
                msg: source.to_string(),
            });
        }

        *self.inner.host_sysctls.lock().expect("host sysctl mutex poisoned") =
            Some(sysctls);

        match wan_iface {
            Some(wan) => info!(
                "Host network ready for v6={pool_v6}: per-cell anti-spoof, \
                 host/sibling isolation, and NAT egress via '{wan}'. Host \
                 firewall chains can still deny this traffic."
            ),
            None => warn!(
                "Host network ready for v6={pool_v6}, but there is no IPv6 \
                 default route — cells remain isolated with no egress."
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
            let mut alias = None;
            let mut is_netkit = false;
            for attr in &link.attributes {
                match attr {
                    LinkAttribute::IfName(n) => name = Some(n.clone()),
                    LinkAttribute::IfAlias(a) => alias = Some(a.clone()),
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
                && alias.as_deref() == Some(CELL_INTERFACE_ALIAS)
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

    async fn ensure_pool_does_not_overlap_routes(
        &self,
        pool: ipnet::Ipv6Net,
    ) -> Result<(), NetworkError> {
        let route_msg = RouteMessageBuilder::<Ipv6Addr>::new().build();
        let mut routes = self.inner.handle.route().get(route_msg).execute();
        while let Some(route) = routes.try_next().await? {
            let prefix_len = route.header.destination_prefix_length;
            if prefix_len == 0
                || route.header.address_family != AddressFamily::Inet6
            {
                continue;
            }
            for attr in &route.attributes {
                let RouteAttribute::Destination(RouteAddress::Inet6(address)) =
                    attr
                else {
                    continue;
                };
                let Ok(existing) = ipnet::Ipv6Net::new(*address, prefix_len)
                else {
                    continue;
                };
                if prefixes_overlap(pool, existing) {
                    return Err(NetworkError::PoolRouteConflict {
                        pool,
                        route: existing.trunc(),
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

fn prefixes_overlap(left: ipnet::Ipv6Net, right: ipnet::Ipv6Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
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

    #[test]
    fn pool_overlap_detects_both_route_widths() {
        let pool: ipnet::Ipv6Net = "fd00:ae::/64".parse().expect("pool");
        let child: ipnet::Ipv6Net = "fd00:ae::1:0/112".parse().expect("child");
        let parent: ipnet::Ipv6Net = "fd00::/8".parse().expect("parent");
        let other: ipnet::Ipv6Net = "fd01::/64".parse().expect("other");

        assert!(prefixes_overlap(pool, child));
        assert!(prefixes_overlap(pool, parent));
        assert!(!prefixes_overlap(pool, other));
    }

    /// The startup sweep must delete only netkit primaries with both Aurae's
    /// name shape and durable alias. Either marker alone is insufficient.
    ///
    /// This test deletes an Aurae-marked netkit device on the host, as the
    /// startup of the daemon does. Do not run the root tests on a host with
    /// a production auraed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // This test changes global host netlink state.
    #[serial]
    async fn leftover_sweep_removes_only_cell_primaries() {
        skip_if_not_root!("leftover_sweep_removes_only_cell_primaries");
        skip_if_seccomp!("leftover_sweep_removes_only_cell_primaries");

        let network =
            Network::connect(IpamConfig::default()).expect("netlink connect");
        let handle = &network.inner.handle;
        let (owned, owned_peer) = network.reserve_interface_names();
        let (unmarked, unmarked_peer) = network.reserve_interface_names();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let bystander = format!("tst-{}", &suffix[..8]);
        let bystander_peer = format!("{bystander}-p");

        create_test_pair_with_alias(
            handle,
            &owned,
            &owned_peer,
            Some(CELL_INTERFACE_ALIAS),
        )
        .await;
        create_test_pair(handle, &unmarked, &unmarked_peer).await;
        create_test_pair_with_alias(
            handle,
            &bystander,
            &bystander_peer,
            Some(CELL_INTERFACE_ALIAS),
        )
        .await;

        network.cleanup_leftover_cell_interfaces().await.expect("cleanup");

        let owned_gone = get_link_index(handle, owned.clone()).await.is_err();
        let unmarked_kept =
            get_link_index(handle, unmarked.clone()).await.is_ok();
        let bystander_kept =
            get_link_index(handle, bystander.clone()).await.is_ok();

        delete_if_exists(handle, &owned).await;
        delete_if_exists(handle, &unmarked).await;
        delete_if_exists(handle, &bystander).await;

        assert!(
            owned_gone,
            "sweep must remove an Aurae-named and Aurae-marked primary"
        );
        assert!(
            unmarked_kept,
            "sweep must not remove an unmarked nk-<hex> primary"
        );
        assert!(
            bystander_kept,
            "sweep must not remove a marked device outside Aurae's names"
        );
    }
}
