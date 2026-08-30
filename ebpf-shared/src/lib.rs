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
#![no_std]

pub trait HasCgroup {
    fn cgroup_id(&self) -> u64;
}

pub trait HasHostPid {
    fn host_pid(&self) -> i32;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signal {
    pub cgroup_id: u64,
    pub signum: i32,
    pub pid: i32,
}

impl HasCgroup for Signal {
    fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }
}

impl HasHostPid for Signal {
    fn host_pid(&self) -> i32 {
        self.pid
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkedProcess {
    pub parent_pid: i32,
    pub child_pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExit {
    pub pid: i32,
}

/// The network policy of one cell. The `guard-tcx-cell-net` program reads
/// it from the `CELL_CONFIG` map, keyed by the ifindex of the host-side
/// netkit primary. The struct has 20 bytes and no implicit padding, thus
/// both sides of the map can read it as plain bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellNetConfig {
    /// The delegated prefix of the cell, in network byte order. The source
    /// address of each packet from the cell must be in this prefix.
    pub allowed_net: [u8; 16],
    /// The length of the prefix in bits. A process cell uses 128. A VM
    /// cell that receives a full prefix uses a smaller value.
    pub prefix_len: u32,
}

/// The datapath counters of one cell. They are in the per-CPU
/// `CELL_STATS` map, keyed by the ifindex of the host-side netkit primary.
/// Userspace adds the values of all CPUs. The struct has 40 bytes and no
/// implicit padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CellNetStats {
    /// The packets that the guard dropped, because the source address was
    /// outside the delegated prefix of the cell.
    pub spoof_dropped: u64,
    /// Calls to `bpf_redirect_peer` for packets whose destination matched
    /// another cell. The kernel resolves the peer after the program returns,
    /// so this counter records attempts rather than confirmed deliveries.
    pub redirect_attempted: u64,
    /// Prefix matches whose identity-bearing target was absent. This can
    /// indicate device unregister racing with userspace reconciliation.
    /// The packet falls back to the nft/host-stack path.
    pub redirect_missed: u64,
    /// The packets that the guard gave to the host stack for the
    /// gateway-local delivery or for the NAT egress.
    pub passed: u64,
    /// The packets that the guard dropped for a different reason, for
    /// example a non-IPv6 packet or a damaged header.
    pub other_dropped: u64,
}

/// True if `addr` is in `net` with the length `prefix_len`. The function
/// uses two u64 halves and variable shifts. It has no loop and no 128-bit
/// shift. Thus the BPF verifier accepts it, and bpf-linker needs no
/// compiler-rt call.
#[inline(always)]
pub fn ipv6_in_prefix(
    addr: &[u8; 16],
    net: &[u8; 16],
    prefix_len: u32,
) -> bool {
    #[inline(always)]
    fn mask64(bits: u32) -> u64 {
        // The `bits` value is from 0 to 64. A shift of a u64 by 64 is
        // undefined behaviour, thus 0 bits is a separate case.
        if bits == 0 { 0 } else { !0u64 << (64 - bits) }
    }
    #[inline(always)]
    fn halves(bytes: &[u8; 16]) -> (u64, u64) {
        let mut hi = [0u8; 8];
        let mut lo = [0u8; 8];
        hi.copy_from_slice(&bytes[..8]);
        lo.copy_from_slice(&bytes[8..]);
        (u64::from_be_bytes(hi), u64::from_be_bytes(lo))
    }

    let plen = if prefix_len > 128 { 128 } else { prefix_len };
    let hi_bits = if plen > 64 { 64 } else { plen };
    let lo_bits = plen - hi_bits;

    let (a_hi, a_lo) = halves(addr);
    let (n_hi, n_lo) = halves(net);
    (a_hi & mask64(hi_bits)) == (n_hi & mask64(hi_bits))
        && (a_lo & mask64(lo_bits)) == (n_lo & mask64(lo_bits))
}

/// True if a source address is in the delegated prefix of a cell.
///
/// This is deliberately identical to the nftables source policy that remains
/// active when the BPF guard is absent. In particular, an unspecified source
/// is rejected even for multicast traffic.
#[inline(always)]
pub fn cell_source_allowed(
    saddr: &[u8; 16],
    allowed_net: &[u8; 16],
    prefix_len: u32,
) -> bool {
    ipv6_in_prefix(saddr, allowed_net, prefix_len)
}

/// True for an IPv6 multicast address in `ff00::/8`.
#[inline(always)]
pub fn is_multicast(addr: &[u8; 16]) -> bool {
    addr[0] == 0xFF
}

#[cfg(feature = "user")]
mod user {
    // SAFETY: both types are #[repr(C)] and have no implicit padding.
    // `CellNetConfig` has 16+4 bytes with an alignment of 4, and
    // `CellNetStats` has five 8-byte fields with an alignment of 8. Each
    // field is an integer, thus each bit pattern is a valid value.
    unsafe impl aya::Pod for super::CellNetConfig {}
    unsafe impl aya::Pod for super::CellNetStats {}
}

#[cfg(test)]
mod tests {
    use super::{cell_source_allowed, ipv6_in_prefix};

    fn addr(s: &str) -> [u8; 16] {
        s.parse::<core::net::Ipv6Addr>().unwrap().octets()
    }

    /// The delegated /128 of the cell in the test, and the /128 of a
    /// sibling cell.
    const SELF_NET: &str = "fd00:ae::2";
    const SIBLING: &str = "fd00:ae::3";

    #[test]
    fn network_map_types_have_stable_abi_sizes() {
        assert_eq!(core::mem::size_of::<super::CellNetConfig>(), 20);
        assert_eq!(core::mem::size_of::<super::CellNetStats>(), 40);
    }

    #[test]
    fn in_prefix_source_is_allowed() {
        let net = addr(SELF_NET);
        assert!(cell_source_allowed(&net, &net, 128));
    }

    #[test]
    fn off_prefix_source_is_rejected() {
        let net = addr(SELF_NET);
        assert!(!cell_source_allowed(&addr(SIBLING), &net, 128));
        assert!(!cell_source_allowed(&addr("fd00:ae::1"), &net, 128));
    }

    #[test]
    fn unspecified_source_is_rejected() {
        let net = addr(SELF_NET);
        assert!(!cell_source_allowed(&addr("::"), &net, 128));
    }

    #[test]
    fn wider_delegation_admits_its_whole_prefix() {
        // A VM cell receives a prefix and not one address.
        let net = addr("fd00:ae:0:0:1::");
        assert!(cell_source_allowed(&addr("fd00:ae:0:0:1:dead::5"), &net, 80));
        assert!(!cell_source_allowed(&addr("fd00:ae:0:0:2::5"), &net, 80));
    }

    #[test]
    fn full_length_prefix_matches_exact_address_only() {
        let net = addr("fd00:ae::2");
        assert!(ipv6_in_prefix(&addr("fd00:ae::2"), &net, 128));
        assert!(!ipv6_in_prefix(&addr("fd00:ae::3"), &net, 128));
    }

    #[test]
    fn zero_length_prefix_matches_everything() {
        let net = addr("::");
        assert!(ipv6_in_prefix(&addr("fd00:ae::2"), &net, 0));
        assert!(ipv6_in_prefix(&addr("2001:db8::1"), &net, 0));
    }

    #[test]
    fn prefix_boundaries_within_high_half() {
        let net = addr("fd00:ae::");
        assert!(ipv6_in_prefix(&addr("fd00:ae:ffff::1"), &net, 32));
        assert!(!ipv6_in_prefix(&addr("fd00:af::1"), &net, 32));
        // fc00::1 is different from fd00:: in bit 8 only. Thus it is in
        // the /7 and outside the /8.
        assert!(ipv6_in_prefix(&addr("fc00::1"), &addr("fd00::"), 7));
        assert!(!ipv6_in_prefix(&addr("fc00::1"), &addr("fd00::"), 8));
        // fd80::1 is different from fd00:: in bit 9 only. Thus it is in
        // the /8 and outside the /9.
        assert!(ipv6_in_prefix(&addr("fd80::1"), &addr("fd00::"), 8));
        assert!(!ipv6_in_prefix(&addr("fd80::1"), &addr("fd00::"), 9));
    }

    #[test]
    fn prefix_boundaries_at_and_past_the_split() {
        let net = addr("fd00:ae::");
        // The prefix ends at the u64 boundary.
        assert!(ipv6_in_prefix(&addr("fd00:ae::ffff:ffff"), &net, 64));
        assert!(!ipv6_in_prefix(&addr("fd00:af::"), &net, 64));
        // The low half is part of the comparison.
        assert!(ipv6_in_prefix(&addr("fd00:ae::1:0"), &net, 65));
        assert!(!ipv6_in_prefix(&addr("fd00:ae:0:0:8000::"), &net, 65));
        // A /127 holds two addresses.
        assert!(ipv6_in_prefix(&addr("fd00:ae::1"), &net, 127));
        assert!(!ipv6_in_prefix(&addr("fd00:ae::2"), &net, 127));
    }

    #[test]
    fn oversized_prefix_len_clamps_to_128() {
        let net = addr("fd00:ae::2");
        assert!(ipv6_in_prefix(&addr("fd00:ae::2"), &net, 200));
        assert!(!ipv6_in_prefix(&addr("fd00:ae::3"), &net, 200));
    }
}
