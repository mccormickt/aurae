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
    /// The address on the NIC of the daemon. The NIC always binds it at
    /// /128. Refer to [`crate::init::network::Network::init_endpoint`].
    pub guest_v6: Ipv6Addr,
    /// The width of the block that the host delegated to this endpoint. The
    /// endpoint always binds `guest_v6` at /128. This prefix is the block
    /// that the endpoint can sub-delegate with [`Self::nested_ipam_config`],
    /// for example to give a /128 to each VM in a VM-hosting cell. It is
    /// also the block that the host routes to the endpoint and that the
    /// cell-net guard accepts as the source range. A cell without
    /// sub-delegation uses /128.
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

    /// The IPAM config a nested auraed should seed itself with so it can host
    /// VMs inside its cell. The cell carries a delegated block on `eth0`
    /// (`guest_v6` truncated to `delegated_prefix_len_v6`); the nested auraed
    /// treats that block as its pool and sub-delegates /128s to each VM —
    /// mirroring how the host carves /112s out of the /64 ULA pool. The
    /// block base is the cell's own `eth0` address and the nested gateway is
    /// base+1, so the nested allocator (which reserves both) hands the first
    /// VM base+2.
    ///
    /// Returns `None` when the delegated block is too small to host a VM.
    /// With a /128 device prefix the nested allocator reserves the block base
    /// (the cell's own `eth0`) and base+1 (the nested gateway) and hands the
    /// first VM base+2, so the block needs at least three /128s — a delegated
    /// prefix of /126 or wider. A narrower block (a single-address /128, or a
    /// /127) can't sub-delegate, so its nested auraed runs without a service
    /// `Network` and VM RPCs are refused.
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
    fn nested_ipam_config_uses_the_delegated_block_as_pool() {
        // A /112 cell delegates a 16-bit block; its nested auraed seeds an
        // IPAM whose pool is that block and whose device prefix is /128.
        let config = NetworkConfig {
            host_v6: "fd00:ae::1".parse().unwrap(),
            guest_v6: "fd00:ae::1:0".parse().unwrap(),
            delegated_prefix_len_v6: 112,
            interface_name: "nk-deadbeef-p".to_string(),
        };
        let ipam = config.nested_ipam_config().expect("/112 sub-delegates");
        // First nested allocation is the cell block's base+2 (base is the
        // cell's own eth0, base+1 the nested gateway).
        let alloc = Ipam::new(ipam).allocate("vm:one").unwrap();
        assert_eq!(alloc.guest_ip, "fd00:ae::1:2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(alloc.host_ip, "fd00:ae::1:1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(alloc.delegated.prefix_len(), 128);
    }

    #[test]
    fn nested_ipam_config_none_for_too_narrow_block() {
        // A block with fewer than three /128s can't sub-delegate (it has no
        // room beyond the cell's eth0 + the nested gateway), so its nested
        // auraed gets no service Network and refuses VM hosting. /128 (single
        // address) and /127 (two addresses) are both too narrow; /126 (four)
        // is the first width that can host a VM.
        let cfg = |len: u8| NetworkConfig {
            host_v6: "fd00:ae::1".parse().unwrap(),
            guest_v6: "fd00:ae::4".parse().unwrap(),
            delegated_prefix_len_v6: len,
            interface_name: "eth0".to_string(),
        };
        assert!(cfg(128).nested_ipam_config().is_none(), "/128 too narrow");
        assert!(cfg(127).nested_ipam_config().is_none(), "/127 too narrow");

        let ipam = cfg(126).nested_ipam_config().expect("/126 sub-delegates");
        // Block base fd00:ae::4 = eth0, base+1 = gateway, base+2 = first VM.
        let alloc = Ipam::new(ipam).allocate("vm:one").unwrap();
        assert_eq!(alloc.guest_ip, "fd00:ae::6".parse::<Ipv6Addr>().unwrap());
    }
}
