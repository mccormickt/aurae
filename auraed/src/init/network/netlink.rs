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

//! Async wrappers for the rtnetlink link, address, and route operations.
//!
//! `Network` holds the policy, and this module holds the mechanism. Each
//! item here is a free function that takes a `&Handle`. The functions keep
//! no state and operate on the host network namespace and on the network namespace of a cell.

use super::NetworkError;
use futures::stream::TryStreamExt;
use ipnet::Ipv6Net;
use netlink_packet_route::link::{LinkAttribute, LinkFlags};
use nix::libc;
use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

/// Configure a host-side routed endpoint. The function adds `host/128`,
/// sets the link up, and installs a `dev` route for the delegated guest
/// prefix through that link.
pub(super) async fn configure_routed_endpoint(
    handle: &Handle,
    iface: &str,
    host: Ipv6Addr,
    delegated: Ipv6Net,
) -> Result<(), NetworkError> {
    // Resolve the ifindex of the primary one time and use it for the
    // three operations.
    let link_index = get_link_index(handle, iface.to_string()).await?;

    let host_net = Ipv6Net::new(host, 128).expect("/128 is a valid prefix");
    add_address(handle, link_index, iface, host_net).await?;

    set_link_up(handle, link_index, iface).await?;

    add_dev_route(handle, link_index, iface, delegated, host).await?;
    Ok(())
}

pub(super) async fn configure_loopback(
    handle: &Handle,
) -> Result<(), NetworkError> {
    const LOOPBACK_DEV: &str = "lo";
    const LOOPBACK_IPV6: &str = "::1";
    const LOOPBACK_IPV6_SUBNET: &str = "/128";

    trace!("configure {LOOPBACK_DEV}");
    let link_index = get_link_index(handle, LOOPBACK_DEV.to_owned()).await?;
    add_address(
        handle,
        link_index,
        LOOPBACK_DEV,
        format!("{LOOPBACK_IPV6}{LOOPBACK_IPV6_SUBNET}")
            .parse::<Ipv6Net>()
            .expect("valid ipv6 address"),
    )
    .await?;
    set_link_up(handle, link_index, LOOPBACK_DEV).await?;
    info!("Successfully configured {}", LOOPBACK_DEV);
    Ok(())
}

/// Poll for a link with the given name and return its ifindex. The caller
/// then uses that index for the subsequent operations.
pub(super) async fn wait_for_link(
    handle: &Handle,
    iface: &str,
    timeout: Duration,
    poll_every: Duration,
) -> Result<u32, NetworkError> {
    let start = Instant::now();
    loop {
        match get_link_index(handle, iface.to_string()).await {
            Ok(index) => return Ok(index),
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

/// Add an address to a link with a known index. The `iface` parameter is
/// for the diagnostic messages only.
pub(super) async fn add_address(
    handle: &Handle,
    link_index: u32,
    iface: &str,
    ip: Ipv6Net,
) -> Result<(), NetworkError> {
    handle
        .address()
        .add(link_index, IpAddr::V6(ip.addr()), ip.prefix_len())
        .execute()
        .await
        .map(|_| trace!("Added address to link {iface}"))
        .or_else(|e| {
            // The kernel keys an address to its interface. Thus EEXIST
            // shows that this address is already on this link, and the
            // function can ignore the error. A route is different.
            if netlink_errno(&e) == Some(-libc::EEXIST) {
                warn!("Address {ip} already present on {iface}, ignoring");
                return Ok(());
            }
            Err(NetworkError::ErrorAddingAddress {
                iface: iface.to_string(),
                ip,
                source: e,
            })
        })?;
    Ok(())
}

/// Set a link with a known index admin-up and wait for `IFF_UP`.
pub(super) async fn set_link_up(
    handle: &Handle,
    link_index: u32,
    iface: &str,
) -> Result<(), NetworkError> {
    const TIMEOUT: Duration = Duration::from_secs(3);
    const POLL: Duration = Duration::from_millis(25);

    let msg = LinkUnspec::new_with_index(link_index).up().build();
    handle.link().set(msg).execute().await.map_err(|e| {
        NetworkError::ErrorSettingLinkUp { iface: iface.to_string(), source: e }
    })?;

    // Poll for admin-up (IFF_UP) and not for carrier. A pair device such
    // as netkit raises the carrier only when both halves are up, and the
    // host-side primary comes up before the peer in the cell. The
    // subsequent address and route operations need admin-up only. A DAD
    // wait is also unnecessary, because netkit sets IFF_NOARP and an
    // address does not become tentative. On a timeout the function logs a
    // warning and continues, because the request above was successful.
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

/// Rename a link with a known index. The function sends `RTM_SETLINK` with
/// a new `IFLA_IFNAME`. A rename does not change the ifindex. the
/// index of the caller stays valid.
pub(super) async fn rename_link(
    handle: &Handle,
    link_index: u32,
    old: &str,
    new: &str,
) -> Result<(), NetworkError> {
    let msg =
        LinkUnspec::new_with_index(link_index).name(new.to_string()).build();
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

/// Get the negative errno from a netlink NACK. The caller can then
/// classify a kernel response such as `-EEXIST` or `-ENODEV`. The function
/// returns `None` for each other error.
pub(super) fn netlink_errno(err: &rtnetlink::Error) -> Option<i32> {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        msg.code.map(|c| c.get())
    } else {
        None
    }
}

pub(super) async fn get_link_index(
    handle: &Handle,
    iface: String,
) -> Result<u32, NetworkError> {
    let link = handle
        .link()
        .get()
        .match_name(iface.clone())
        .execute()
        .try_next()
        .await?;
    match link {
        Some(link) => Ok(link.header.index),
        None => Err(NetworkError::DeviceNotFound { iface }),
    }
}

/// Install the v6 host route `dest dev iface src host_ip`. A point-to-link
/// route needs no gateway. The function takes a known link index.
///
/// The function sends `NLM_F_REPLACE` and not `NLM_F_EXCL`. EEXIST shows
/// only that a route to the prefix exists, not that the route points at
/// this device. With `NLM_F_EXCL` an old route through a dead device would
/// stay and would discard the return traffic of the new endpoint. Such a
/// route can come from a daemon that crashed, or from a hard kill during
/// the reallocation of the address.
pub(super) async fn add_dev_route(
    handle: &Handle,
    link_index: u32,
    iface: &str,
    dest: Ipv6Net,
    pref_source: Ipv6Addr,
) -> Result<(), NetworkError> {
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dest.addr(), dest.prefix_len())
        .output_interface(link_index)
        .pref_source(pref_source)
        .build();
    handle.route().add(route).replace().execute().await.map_err(|e| {
        NetworkError::ErrorAddingRoute {
            iface: iface.to_string(),
            route: dest,
            source: e,
        }
    })?;
    Ok(())
}

/// Install the default route `default via <gw> dev iface onlink`. The
/// `onlink` flag lets the kernel install the route although the gateway
/// address is in no attached subnet. The guest side uses a /128 address.
/// The gateway is outside the prefix of the guest.
///
/// The function sends `NLM_F_REPLACE`. It replaces an old default
/// route instead of a failure with EEXIST.
pub(super) async fn add_onlink_default(
    handle: &Handle,
    link_index: u32,
    iface: &str,
    gateway: Ipv6Addr,
    pref_source: Ipv6Addr,
) -> Result<(), NetworkError> {
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
            route: Ipv6Net::default(),
            source: e,
        }
    })?;
    Ok(())
}

pub(super) async fn get_link_name(
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
    use super::super::testutil::*;
    use super::super::{Network, ipam::IpamConfig};
    use super::*;
    use rtnetlink::packet_core::ErrorMessage;
    use serial_test::serial;
    use std::num::NonZeroI32;
    use test_helpers::*;

    #[test]
    fn netlink_errno_classifies_only_nack_replies() {
        let mut nack = ErrorMessage::default();
        nack.code = NonZeroI32::new(-libc::ENODEV);
        assert_eq!(
            netlink_errno(&rtnetlink::Error::NetlinkError(nack)),
            Some(-libc::ENODEV)
        );

        // An ACK has the code `None` and no errno.
        assert_eq!(
            netlink_errno(&rtnetlink::Error::NetlinkError(
                ErrorMessage::default()
            )),
            None
        );

        // A different error variant also has no errno.
        assert_eq!(
            netlink_errno(&rtnetlink::Error::NamespaceError("x".into())),
            None
        );
    }

    /// `add_dev_route` must replace an old route to the same prefix that
    /// points at a different device. With `NLM_F_EXCL` the second add
    /// fails with EEXIST, and the old route continues to discard the
    /// return traffic of the new endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // This test changes global host netlink state.
    #[serial]
    async fn dev_route_replace_supersedes_stale_route() {
        skip_if_not_root!("dev_route_replace_supersedes_stale_route");
        skip_if_seccomp!("dev_route_replace_supersedes_stale_route");

        let network =
            Network::connect(IpamConfig::default()).expect("netlink connect");
        let handle = &network.inner.handle;
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
            let stale_idx = get_link_index(handle, stale.clone()).await?;
            let fresh_idx = get_link_index(handle, fresh.clone()).await?;
            add_address(
                handle,
                stale_idx,
                &stale,
                Ipv6Net::new(host, 128).expect("/128"),
            )
            .await?;
            set_link_up(handle, stale_idx, &stale).await?;
            set_link_up(handle, fresh_idx, &fresh).await?;
            // Add the old route through the stale device.
            add_dev_route(handle, stale_idx, &stale, dest, host).await?;
            // The route of the new endpoint must replace it.
            add_dev_route(handle, fresh_idx, &fresh, dest, host).await?;
            Ok(())
        }
        .await;

        let oif = route_oif(handle, dest).await;
        let fresh_idx = get_link_index(handle, fresh.clone()).await.ok();

        // Delete the devices before the assertions, so that a failure
        // does not leak a device. The routes end with the links.
        delete_if_exists(handle, &stale).await;
        delete_if_exists(handle, &fresh).await;

        setup.expect("route setup");
        assert_eq!(
            oif, fresh_idx,
            "the route must point at the replacing device, not the stale one"
        );
    }
}
