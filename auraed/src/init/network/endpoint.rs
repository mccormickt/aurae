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

//! Per-endpoint network configuration shared by Pid1 and Cell runtimes.
//!
//! A single auraed coming up in its own netns (a true netns for cells; the
//! VM kernel's namespace for Pid1) configures its own NIC from this struct.
//! The same shape is used for both runtimes — only the input source differs:
//! cells get this via CLI flags from the parent auraed; Pid1 gets it via CLI
//! flags or, for legacy VM-boot paths, by parsing `/proc/cmdline`.
//!
//! Coordination for nested-auraed cells is one-way: parent → child via argv.
//! The parent sets up the host side (creates the interface pair, moves the
//! peer in, configures the host primary). The child reads these flags and
//! configures the peer from inside its netns. This avoids any need for the
//! parent to enter the cell's netns, while staying within rtnetlink's
//! constraints (address/route operations don't accept a target-netnsid
//! attribute).
//!
//! The peer's name in the parent netns is unique (e.g., `nk-a1b2c3d4-p`) so
//! it can't collide with the host's `eth0`. The child reads the unique name
//! and renames the link to `eth0` after it lands in the cell's netns —
//! at which point the name is local to that netns and can't conflict with
//! anything on the host. VM scenarios typically already have an `eth0` and
//! the rename step is a no-op.

use crate::init::network::ipam::Allocation;
use std::net::Ipv6Addr;

/// CLI flag names. The values match the long names clap derives from
/// the snake-case fields on `AuraedOptions` (`net_host_ip_v6` →
/// `--net-host-ip-v6`); keeping them as constants here so the parent
/// uses the same names the child will accept.
pub const FLAG_HOST_IP_V6: &str = "--net-host-ip-v6";
pub const FLAG_GUEST_IP_V6: &str = "--net-guest-ip-v6";
pub const FLAG_GUEST_PREFIX_V6: &str = "--net-guest-prefix-v6";
pub const FLAG_INTERFACE_NAME: &str = "--net-interface-name";

/// Per-endpoint network configuration: what one auraed needs to bring up
/// its own NIC inside its own netns.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Per-pool host gateway. The `onlink` default route points here.
    pub host_v6: Ipv6Addr,
    /// Address bound on the daemon's NIC.
    pub guest_v6: Ipv6Addr,
    /// Prefix length to bind `guest_v6` at. /128 for cells (single
    /// address); /80 (or similar) for nested-auraed / VM scenarios that
    /// want a delegated prefix on the NIC.
    pub guest_prefix_len_v6: u8,
    /// Name the NIC has when the daemon starts up. The daemon waits for
    /// a link with this name to appear, renames it to `eth0` if it
    /// isn't already, and configures `eth0`. Cells get a unique
    /// parent-chosen peer name (`nk-<hex>-p`); VMs typically have
    /// `eth0` already.
    pub interface_name: String,
}

impl NetworkConfig {
    /// Build from an IPAM allocation and the interface name the parent
    /// will use when creating the cell's interface pair. `host_ip` is the
    /// shared per-pool gateway; `guest_ip` is the cell-specific endpoint
    /// address; the prefix length comes from the allocation's delegated
    /// prefix.
    pub fn from_allocation(
        allocation: &Allocation,
        interface_name: String,
    ) -> Self {
        Self {
            host_v6: allocation.host_ip,
            guest_v6: allocation.guest_ip,
            guest_prefix_len_v6: allocation.delegated.prefix_len(),
            interface_name,
        }
    }

    /// Render as `(flag, value)` pairs ready for `Command::args`.
    pub fn as_cli_args(&self) -> [(&'static str, String); 4] {
        [
            (FLAG_HOST_IP_V6, self.host_v6.to_string()),
            (FLAG_GUEST_IP_V6, self.guest_v6.to_string()),
            (FLAG_GUEST_PREFIX_V6, self.guest_prefix_len_v6.to_string()),
            (FLAG_INTERFACE_NAME, self.interface_name.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::network::ipam::Ipam;

    #[test]
    fn from_allocation_round_trips_addresses() {
        let ipam = Ipam::default();
        let alloc = ipam.allocate("cell:test").expect("allocate");
        let config =
            NetworkConfig::from_allocation(&alloc, "nk-a1b2c3d4-p".to_string());
        assert_eq!(config.host_v6, alloc.host_ip);
        assert_eq!(config.guest_v6, alloc.guest_ip);
        assert_eq!(config.guest_prefix_len_v6, alloc.delegated.prefix_len());
        assert_eq!(config.interface_name, "nk-a1b2c3d4-p");
    }

    #[test]
    fn cli_args_use_documented_flag_names() {
        let config = NetworkConfig {
            host_v6: "fd00:ae::1".parse().unwrap(),
            guest_v6: "fd00:ae::2".parse().unwrap(),
            guest_prefix_len_v6: 128,
            interface_name: "nk-deadbeef-p".to_string(),
        };
        let pairs = config.as_cli_args();
        assert_eq!(pairs[0].0, "--net-host-ip-v6");
        assert_eq!(pairs[0].1, "fd00:ae::1");
        assert_eq!(pairs[1].0, "--net-guest-ip-v6");
        assert_eq!(pairs[1].1, "fd00:ae::2");
        assert_eq!(pairs[2].0, "--net-guest-prefix-v6");
        assert_eq!(pairs[2].1, "128");
        assert_eq!(pairs[3].0, "--net-interface-name");
        assert_eq!(pairs[3].1, "nk-deadbeef-p");
    }
}
