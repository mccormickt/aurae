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
/* -------------------------------------------------------------------------- *\
 *                      SPDX-License-Identifier: GPL-2.0                      *
 *                      SPDX-License-Identifier: MIT                          *
 *                                                                            *
 *                +--------------------------------------------+              *
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 *                                                                            *
 * -------------------------------------------------------------------------- *
 * Dual Licensed: GNU GENERAL PUBLIC LICENSE 2.0                              *
 * Dual Licensed: MIT License                                                 *
 * Copyright 2023 The Aurae Authors (The Nivenly Foundation)                  *
\* -------------------------------------------------------------------------- */

//! The network guard of one cell. The host auraed attaches it at tcx
//! ingress on the netkit primary of each cell, on the host netns side.
//!
//! All traffic from a cell goes through its netkit peer and arrives on the
//! RX path of the primary. Thus this hook sees each packet that leaves a
//! cell. Traffic from the host does not pass this hook. The program:
//!
//! 1. fails closed. A device without a `CELL_CONFIG` entry gets a drop.
//! 2. binds the source address to the cell with `cell_source_allowed`. The
//!    source must be in the delegated prefix of the cell. This check is the
//!    same as the per-cell binding in nftables. The nft rules still apply
//!    while this program is detached. Refer to `init/network/bpf.rs`.
//! 3. sends cell-to-cell traffic directly into the netns of the
//!    destination cell with `bpf_redirect_peer()`. The packet stays in the
//!    same softirq and enters neither the host stack nor netfilter.
//! 4. gives all other traffic to the host stack for the gateway-local
//!    delivery and for the NAT egress.
//!
//! A netkit pair of a cell operates in L3 mode, thus a packet here has no
//! Ethernet header. The program reads the header with
//! `bpf_skb_load_bytes_relative(BPF_HDR_START_NET)`, which starts at the
//! network header with or without a MAC header.

#![no_std]
#![no_main]

use aurae_ebpf_shared::{
    cell_source_allowed, is_multicast, CellNetConfig, CellNetStats,
};
use aya_ebpf::bindings::bpf_hdr_start_off::BPF_HDR_START_NET;
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT};
use aya_ebpf::helpers::{bpf_redirect_peer, bpf_skb_load_bytes_relative};
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{DevMapHash, HashMap, LpmTrie, PerCpuHashMap};
use aya_ebpf::programs::TcContext;
use core::ffi::c_void;

#[unsafe(link_section = "license")]
#[used]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

/// `__sk_buff.protocol` holds the big-endian 16-bit ethertype in a u32.
const ETH_P_IPV6_BE: u32 = (0x86DDu16).to_be() as u32;

/// The policy of each cell, keyed by the ifindex of its netkit primary.
/// The host auraed inserts the entry before it attaches the program. A
/// missing entry causes a drop.
#[map(name = "CELL_CONFIG")]
static CELL_CONFIG: HashMap<u32, CellNetConfig> =
    HashMap::with_max_entries(4096, 0);

/// The map from a delegated prefix to the non-reused publication ID of its
/// cell. It is an LPM trie, thus a VM cell can use a prefix shorter than
/// /128. `with_max_entries` adds `BPF_F_NO_PREALLOC`, which the kernel needs
/// for an LPM trie.
#[map(name = "CELL_REDIRECT")]
static CELL_REDIRECT: LpmTrie<[u8; 16], u32> =
    LpmTrie::with_max_entries(8192, 0);

/// The identity-bearing redirect targets. The kernel associates each entry
/// with a specific net_device and removes it on NETDEV_UNREGISTER. A stale
/// prefix therefore cannot redirect to a different device that later reuses
/// the same numeric ifindex. Userspace never reuses a publication ID during
/// the lifetime of these maps.
#[map(name = "CELL_TARGETS")]
static CELL_TARGETS: DevMapHash = DevMapHash::with_max_entries(4096, 0);

/// The counters of each cell, keyed by the ifindex of its netkit primary.
/// The host auraed inserts a zeroed entry before the attach.
#[map(name = "CELL_STATS")]
static CELL_STATS: PerCpuHashMap<u32, CellNetStats> =
    PerCpuHashMap::with_max_entries(4096, 0);

#[classifier]
pub fn cell_ingress(ctx: TcContext) -> i32 {
    match try_cell_ingress(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_cell_ingress(ctx: &TcContext) -> Result<i32, i32> {
    let skb = ctx.skb.skb;
    let ifindex = unsafe { (*skb).ifindex };

    // Fail closed. A device without a policy gets no connectivity. The
    // host auraed inserts the entry before it attaches the program. Thus a
    // miss here shows a recycled ifindex or a bug, and neither condition
    // must pass a packet.
    let Some(cfg_ptr) = CELL_CONFIG.get_ptr(&ifindex) else {
        return Err(TC_ACT_SHOT as i32);
    };
    let cfg = unsafe { &*cfg_ptr };

    // The cell pool is IPv6-only. No other protocol can leave a cell.
    if unsafe { (*skb).protocol } != ETH_P_IPV6_BE {
        count(ifindex, Field::OtherDropped);
        return Err(TC_ACT_SHOT as i32);
    }

    // Read the fixed IPv6 header one time, from the start of the network
    // header. The source is at offset 8 and the destination is at offset
    // 24 of that header. Thus an extension header has no effect here.
    let mut hdr = [0u8; 40];
    let ret = unsafe {
        bpf_skb_load_bytes_relative(
            skb as *const c_void,
            0,
            hdr.as_mut_ptr() as *mut c_void,
            40,
            BPF_HDR_START_NET as u32,
        )
    };
    if ret != 0 || (hdr[0] >> 4) != 6 {
        count(ifindex, Field::OtherDropped);
        return Err(TC_ACT_SHOT as i32);
    }

    let mut saddr = [0u8; 16];
    saddr.copy_from_slice(&hdr[8..24]);
    let mut daddr = [0u8; 16];
    daddr.copy_from_slice(&hdr[24..40]);

    // The per-cell anti-spoof check. `cell_source_allowed` is in
    // `aurae-ebpf-shared`, thus a host-side unit test can call it. A root
    // integration test is not the only test of this decision.
    if !cell_source_allowed(&saddr, &cfg.allowed_net, cfg.prefix_len) {
        count(ifindex, Field::SpoofDropped);
        return Err(TC_ACT_SHOT as i32);
    }

    // The host stack processes multicast. Multicast cannot reach a
    // sibling cell, because the host does no multicast routing and the
    // redirect lookup below accepts unicast only.
    if is_multicast(&daddr) {
        count(ifindex, Field::Passed);
        return Ok(TC_ACT_OK as i32);
    }

    // The cell-to-cell fast path sends the packet directly into the netns
    // of the destination cell. The identity-bearing target map misses after
    // device unregister and then deliberately falls through to the nft/host
    // stack. Once the helper accepts a live target, a later redirect failure
    // drops the packet rather than bypassing policy.
    let key = Key::new(128, daddr);
    if let Some(redirect_id) = CELL_REDIRECT.get(&key) {
        if let Some(target) = CELL_TARGETS.get(*redirect_id) {
            count(ifindex, Field::RedirectAttempted);
            // With the flags value 0 the helper must return TC_ACT_REDIRECT.
            // Change each other result to a drop, so that an unexpected result
            // fails closed. A negative error code must not enter the
            // datapath.
            let ret = unsafe { bpf_redirect_peer(target.if_index, 0) } as i32;
            if ret != TC_ACT_REDIRECT as i32 {
                return Err(TC_ACT_SHOT as i32);
            }
            return Ok(ret);
        }
        count(ifindex, Field::RedirectMissed);
        return Ok(TC_ACT_OK as i32);
    }

    // The host stack processes all other traffic. It does the
    // gateway-local delivery and the NAT egress.
    count(ifindex, Field::Passed);
    Ok(TC_ACT_OK as i32)
}

enum Field {
    SpoofDropped,
    RedirectAttempted,
    RedirectMissed,
    Passed,
    OtherDropped,
}

/// Increase one per-CPU counter of the cell. The function ignores a
/// missing entry. Userspace inserts the entry before the attach, thus a
/// miss occurs only for a recycled ifindex. The configuration check above
/// already fails closed in that condition.
#[inline(always)]
fn count(ifindex: u32, field: Field) {
    if let Some(stats) = CELL_STATS.get_ptr_mut(&ifindex) {
        let stats = unsafe { &mut *stats };
        match field {
            Field::SpoofDropped => stats.spoof_dropped += 1,
            Field::RedirectAttempted => stats.redirect_attempted += 1,
            Field::RedirectMissed => stats.redirect_missed += 1,
            Field::Passed => stats.passed += 1,
            Field::OtherDropped => stats.other_dropped += 1,
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
