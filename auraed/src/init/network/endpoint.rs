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

//! The network configuration of one endpoint. The pid1 runtime and the
//! cell runtime both use it.
//!
//! An auraed that starts in its own network namespace configures its own NIC from this
//! struct. A cell has a true network namespace, and pid1 has the namespace of the VM
//! kernel. Only the source of the values is different. A cell receives them
//! in CLI flags from the parent auraed. Pid1 receives them in CLI flags, or
//! from `/proc/cmdline` on a legacy VM boot path.
//!
//! For a nested auraed the flow is one-way: the parent sends the values to
//! the child in argv. The parent configures the host side. It creates the
//! interface pair, moves the peer, and configures the host primary. The
//! child reads the flags and configures the peer in its own network namespace. Thus the
//! parent does not enter the network namespace of the cell. This is also necessary,
//! because an rtnetlink address or route operation accepts no target network namespace
//! attribute.
//!
//! The peer has a unique name in the parent network namespace, for example
//! `nk-a1b2c3d4-p`. Thus it cannot conflict with the `eth0` of the host.
//! The child reads that name and renames the link to `eth0` after the link
//! is in the network namespace of the cell. The name is then local to that network namespace. A VM
//! usually has an `eth0` already, and the rename does nothing.

use crate::init::network::ipam::{Allocation, IpamConfig};
use ipnet::Ipv6Net;
use std::net::Ipv6Addr;

/// The names of the CLI flags. Each value is the long name that clap
/// derives from the snake-case field of `AuraedOptions`. For example,
/// `net_host_ip_v6` becomes `--net-host-ip-v6`. These constants make sure
/// that the parent sends the names that the child accepts.
pub const FLAG_HOST_IP_V6: &str = "--net-host-ip-v6";
pub const FLAG_GUEST_IP_V6: &str = "--net-guest-ip-v6";
pub const FLAG_DELEGATED_PREFIX_V6: &str = "--net-delegated-prefix-v6";
pub const FLAG_INTERFACE_NAME: &str = "--net-interface-name";

/// The network configuration of one endpoint. An auraed needs these values
/// to set up its own NIC in its own network namespace.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// The host gateway of the pool. The `onlink` default route uses it.
    pub host_v6: Ipv6Addr,
    /// The address on the NIC of the daemon. The endpoint always binds it
    /// at /128, independently of the delegated block size.
    pub guest_v6: Ipv6Addr,
    /// The prefix length of the block routed to this endpoint and accepted
    /// by the source guard. A nested auraed can sub-delegate addresses from
    /// this block to VMs without changing its own /128 endpoint identity.
    pub delegated_prefix_len_v6: u8,
    /// The name of the NIC at the start of the daemon. The daemon waits
    /// for a link with this name, renames it to `eth0`, and configures
    /// `eth0`. The parent gives a cell a unique peer name `nk-<hex>-p`. A
    /// VM usually has `eth0` already.
    pub interface_name: String,
}

impl NetworkConfig {
    /// Build the configuration from an IPAM allocation and the interface
    /// name of the peer. `host_ip` is the common gateway of the pool.
    /// `guest_ip` is the endpoint address of the cell. The prefix length
    /// comes from the delegated prefix of the allocation.
    pub fn from_allocation(
        allocation: &Allocation,
        interface_name: String,
    ) -> Self {
        Self {
            host_v6: allocation.host_ip,
            guest_v6: allocation.guest_ip,
            delegated_prefix_len_v6: allocation.delegated.prefix_len(),
            interface_name,
        }
    }

    /// Give the configuration as `(flag, value)` pairs for
    /// `Command::args`.
    pub fn as_cli_args(&self) -> [(&'static str, String); 4] {
        [
            (FLAG_HOST_IP_V6, self.host_v6.to_string()),
            (FLAG_GUEST_IP_V6, self.guest_v6.to_string()),
            (
                FLAG_DELEGATED_PREFIX_V6,
                self.delegated_prefix_len_v6.to_string(),
            ),
            (FLAG_INTERFACE_NAME, self.interface_name.clone()),
        ]
    }

    /// Build the allocator that a nested auraed can use to sub-delegate
    /// /128 addresses to VMs. The cell endpoint occupies the block base and
    /// the nested gateway occupies base+1, so at least three addresses are
    /// required.
    pub fn nested_ipam_config(&self) -> Option<IpamConfig> {
        if self.delegated_prefix_len_v6 > 126 {
            return None;
        }
        let pool = Ipv6Net::new(self.guest_v6, self.delegated_prefix_len_v6)
            .ok()?
            .trunc();
        IpamConfig::new(pool, 128).ok()
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
        assert_eq!(
            config.delegated_prefix_len_v6,
            alloc.delegated.prefix_len()
        );
        assert_eq!(config.interface_name, "nk-a1b2c3d4-p");
    }

    #[test]
    fn cli_args_use_documented_flag_names() {
        let config = NetworkConfig {
            host_v6: "fd00:ae::1".parse().unwrap(),
            guest_v6: "fd00:ae::2".parse().unwrap(),
            delegated_prefix_len_v6: 128,
            interface_name: "nk-deadbeef-p".to_string(),
        };
        let pairs = config.as_cli_args();
        assert_eq!(pairs[0].0, "--net-host-ip-v6");
        assert_eq!(pairs[0].1, "fd00:ae::1");
        assert_eq!(pairs[1].0, "--net-guest-ip-v6");
        assert_eq!(pairs[1].1, "fd00:ae::2");
        assert_eq!(pairs[2].0, "--net-delegated-prefix-v6");
        assert_eq!(pairs[2].1, "128");
        assert_eq!(pairs[3].0, "--net-interface-name");
        assert_eq!(pairs[3].1, "nk-deadbeef-p");
    }

    #[test]
    fn delegated_block_seeds_nested_vm_ipam() {
        let config = NetworkConfig {
            host_v6: "fd00:ae::1".parse().unwrap(),
            guest_v6: "fd00:ae::1:0".parse().unwrap(),
            delegated_prefix_len_v6: 112,
            interface_name: "eth0".to_string(),
        };
        let nested = config.nested_ipam_config().expect("delegated pool");
        assert_eq!(nested.pool_v6.to_string(), "fd00:ae::1:0/112");
        assert_eq!(nested.device_prefix_v6, 128);

        let allocation = Ipam::new(nested).allocate("vm:one").unwrap();
        assert_eq!(allocation.host_ip.to_string(), "fd00:ae::1:1");
        assert_eq!(allocation.guest_ip.to_string(), "fd00:ae::1:2");
        assert_eq!(allocation.delegated.prefix_len(), 128);
    }

    #[test]
    fn nested_vm_ipam_requires_three_addresses() {
        let config = |delegated_prefix_len_v6| NetworkConfig {
            host_v6: "fd00:ae::1".parse().unwrap(),
            guest_v6: "fd00:ae::4".parse().unwrap(),
            delegated_prefix_len_v6,
            interface_name: "eth0".to_string(),
        };

        assert!(config(128).nested_ipam_config().is_none());
        assert!(config(127).nested_ipam_config().is_none());
        let nested = config(126).nested_ipam_config().expect("four addresses");
        let allocation = Ipam::new(nested).allocate("vm:one").unwrap();
        assert_eq!(allocation.guest_ip.to_string(), "fd00:ae::6");
    }
}
