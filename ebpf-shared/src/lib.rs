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

/// Per-cell network policy consulted by the `guard-tcx-cell-net` program.
/// Keyed by the host-side netkit primary's ifindex in the `CELL_CONFIG`
/// map. 20 bytes, no implicit padding — safe to treat as plain bytes on
/// both sides of the map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellNetConfig {
    /// Network-order (big-endian) bytes of the cell's delegated prefix.
    /// Every packet the cell emits must have a source address inside it.
    pub allowed_net: [u8; 16],
    /// Prefix length in bits. 128 for process cells today; narrower for
    /// future VM cells that delegate a whole prefix to the guest.
    pub prefix_len: u32,
}

/// Per-cell datapath counters kept in the per-CPU `CELL_STATS` map,
/// keyed by the host-side netkit primary's ifindex. Userspace sums
/// across CPUs. 32 bytes, no implicit padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CellNetStats {
    /// Packets dropped because the source address was outside the cell's
    /// delegated prefix.
    pub spoof_dropped: u64,
    /// Packets queued for direct delivery into another cell's netns via
    /// `bpf_redirect_peer`. Counts redirect *attempts*: the kernel
    /// resolves the peer after the program returns and silently drops
    /// the packet when the target device is gone or down.
    pub redirected: u64,
    /// Packets handed to the host stack (gateway-local delivery or NAT
    /// egress).
    pub passed: u64,
    /// Packets dropped for any other reason (non-IPv6, malformed header).
    pub other_dropped: u64,
}

/// True iff `addr` falls inside `net`/`prefix_len`. Operates on two u64
/// halves with variable shifts only — no loops and no 128-bit shifts, so
/// the BPF side verifies trivially and bpf-linker never needs a
/// compiler-rt libcall.
#[inline(always)]
pub fn ipv6_in_prefix(
    addr: &[u8; 16],
    net: &[u8; 16],
    prefix_len: u32,
) -> bool {
    #[inline(always)]
    fn mask64(bits: u32) -> u64 {
        // bits is in [0, 64]; shifting u64 by 64 is UB, so 0 bits is its
        // own case.
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

#[cfg(feature = "user")]
mod user {
    // SAFETY: both types are #[repr(C)] with no implicit padding
    // (CellNetConfig: 16+4 bytes, align 4; CellNetStats: 4x8 bytes,
    // align 8) and contain only integer fields, so any bit pattern is a
    // valid value.
    unsafe impl aya::Pod for super::CellNetConfig {}
    unsafe impl aya::Pod for super::CellNetStats {}
}

#[cfg(test)]
mod tests {
    use super::ipv6_in_prefix;

    fn addr(s: &str) -> [u8; 16] {
        s.parse::<core::net::Ipv6Addr>().unwrap().octets()
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
        // fc00::1 differs from fd00:: only in the 8th bit: inside /7,
        // outside /8.
        assert!(ipv6_in_prefix(&addr("fc00::1"), &addr("fd00::"), 7));
        assert!(!ipv6_in_prefix(&addr("fc00::1"), &addr("fd00::"), 8));
        // fd80::1 differs from fd00:: only in the 9th bit: inside /8,
        // outside /9.
        assert!(ipv6_in_prefix(&addr("fd80::1"), &addr("fd00::"), 8));
        assert!(!ipv6_in_prefix(&addr("fd80::1"), &addr("fd00::"), 9));
    }

    #[test]
    fn prefix_boundaries_at_and_past_the_split() {
        let net = addr("fd00:ae::");
        // Exactly the u64 split.
        assert!(ipv6_in_prefix(&addr("fd00:ae::ffff:ffff"), &net, 64));
        assert!(!ipv6_in_prefix(&addr("fd00:af::"), &net, 64));
        // Low half participates.
        assert!(ipv6_in_prefix(&addr("fd00:ae::1:0"), &net, 65));
        assert!(!ipv6_in_prefix(&addr("fd00:ae:0:0:8000::"), &net, 65));
        // /127 pairs.
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
