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

//! Per-cell network guard, attached by the host auraed at tc(x) ingress on
//! every cell's netkit primary (host netns side).
//!
//! All traffic a cell emits traverses its netkit peer and surfaces on the
//! primary's RX path, so this single hook point sees every packet leaving
//! a cell — host-originated traffic never passes here. The program:
//!
//! 1. fails closed — no `CELL_CONFIG` entry for this device means drop;
//! 2. enforces per-cell source-address binding ("siblings are
//!    adversaries"): the source must sit inside the cell's delegated
//!    prefix, which is strictly stronger than the pool-granularity
//!    nftables rule;
//! 3. delivers cell→cell traffic straight into the destination cell's
//!    netns with `bpf_redirect_peer()` (same-softirq, no host stack and
//!    no netfilter traversal);
//! 4. hands everything else to the host stack (gateway-local delivery,
//!    NAT egress).
//!
//! Cell netkit pairs run in L3 mode, so packets here carry no Ethernet
//! header. Reads use `bpf_skb_load_bytes_relative(BPF_HDR_START_NET)`,
//! which is anchored at the network header whether or not a MAC header
//! exists.

#![no_std]
#![no_main]

use aurae_ebpf_shared::{ipv6_in_prefix, CellNetConfig, CellNetStats};
use aya_ebpf::bindings::bpf_hdr_start_off::BPF_HDR_START_NET;
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::{bpf_redirect_peer, bpf_skb_load_bytes_relative};
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{HashMap, LpmTrie, PerCpuHashMap};
use aya_ebpf::programs::TcContext;
use core::ffi::c_void;

#[unsafe(link_section = "license")]
#[used]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

/// `__sk_buff.protocol` holds the be16 ethertype zero-extended to u32.
const ETH_P_IPV6_BE: u32 = (0x86DDu16).to_be() as u32;

/// Per-cell policy, keyed by the netkit primary's ifindex. Inserted by
/// the host auraed before the program is attached; missing entry ⇒ drop.
#[map(name = "CELL_CONFIG")]
static CELL_CONFIG: HashMap<u32, CellNetConfig> =
    HashMap::with_max_entries(4096, 0);

/// Delegated prefix → netkit primary ifindex of the owning cell. An LPM
/// trie so VM cells can later delegate prefixes wider than /128.
/// (`with_max_entries` ORs in `BPF_F_NO_PREALLOC`, which the kernel
/// requires for LPM tries.)
#[map(name = "CELL_REDIRECT")]
static CELL_REDIRECT: LpmTrie<[u8; 16], u32> =
    LpmTrie::with_max_entries(8192, 0);

/// Per-cell counters, keyed by the netkit primary's ifindex. Zeroed
/// entries are inserted by the host auraed before attach.
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

    // Fail closed: a device without policy gets no connectivity. The
    // host auraed inserts the entry before it attaches the program, so
    // a miss here is either a recycled ifindex or a bug — both must not
    // leak packets.
    let Some(cfg_ptr) = CELL_CONFIG.get_ptr(&ifindex) else {
        return Err(TC_ACT_SHOT as i32);
    };
    let cfg = unsafe { &*cfg_ptr };

    // The cell pool is IPv6-only; nothing else has any business leaving
    // a cell.
    if unsafe { (*skb).protocol } != ETH_P_IPV6_BE {
        count(ifindex, Field::OtherDropped);
        return Err(TC_ACT_SHOT as i32);
    }

    // One bounded read of the fixed IPv6 header, anchored at the network
    // header. Source/destination live at fixed offsets 8/24 of the fixed
    // header, so extension headers never matter here.
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

    // Multicast goes to the host stack before the source check: MLD
    // reports may carry an unspecified source (L3 netkit peers have no
    // link-local address). The host does no multicast routing, so this
    // can never reach a sibling cell.
    if daddr[0] == 0xFF {
        count(ifindex, Field::Passed);
        return Ok(TC_ACT_OK as i32);
    }

    // Per-cell anti-spoof: the source address must be inside this cell's
    // delegated prefix.
    if !ipv6_in_prefix(&saddr, &cfg.allowed_net, cfg.prefix_len) {
        count(ifindex, Field::SpoofDropped);
        return Err(TC_ACT_SHOT as i32);
    }

    // Cell→cell fast path: deliver straight into the destination cell's
    // netns. With flags == 0 the helper always returns TC_ACT_REDIRECT;
    // the kernel resolves the peer after this program returns (in
    // skb_do_redirect) and frees the packet when the target device is
    // gone or down — a failed redirect therefore fails closed rather
    // than falling through to the host stack.
    let key = Key::new(128, daddr);
    if let Some(target) = CELL_REDIRECT.get(&key) {
        count(ifindex, Field::Redirected);
        return Ok(unsafe { bpf_redirect_peer(*target, 0) } as i32);
    }

    // Everything else is the host stack's job: gateway-local delivery
    // and (NATed) world egress.
    count(ifindex, Field::Passed);
    Ok(TC_ACT_OK as i32)
}

enum Field {
    SpoofDropped,
    Redirected,
    Passed,
    OtherDropped,
}

/// Bump one per-CPU counter for the cell. A missing stats entry is
/// silently ignored: userspace inserts it before attach, so a miss can
/// only happen in the same recycled-ifindex window the config check
/// already fails closed on.
#[inline(always)]
fn count(ifindex: u32, field: Field) {
    if let Some(stats) = CELL_STATS.get_ptr_mut(&ifindex) {
        let stats = unsafe { &mut *stats };
        match field {
            Field::SpoofDropped => stats.spoof_dropped += 1,
            Field::Redirected => stats.redirected += 1,
            Field::Passed => stats.passed += 1,
            Field::OtherDropped => stats.other_dropped += 1,
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
