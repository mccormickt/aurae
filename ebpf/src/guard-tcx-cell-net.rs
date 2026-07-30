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
//! 3. gives all other traffic to the host stack. The nftables ruleset of
//!    the host then decides the forwarding: gateway-local delivery, NAT
//!    egress, and the drop of cell-to-cell and cell-to-host traffic. The
//!    program makes no forwarding decision of its own, thus the policy is
//!    the same with and without the program.
//!
//! A netkit pair of a cell operates in L3 mode, thus a packet here has no
//! Ethernet header. The program reads the header with
//! `bpf_skb_load_bytes_relative(BPF_HDR_START_NET)`, which starts at the
//! network header with or without a MAC header.

#![no_std]
#![no_main]

use aurae_ebpf_shared::{CellNetConfig, CellNetStats, cell_source_allowed};
use aya_ebpf::bindings::bpf_hdr_start_off::BPF_HDR_START_NET;
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_skb_load_bytes_relative;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{HashMap, PerCpuHashMap};
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

    // Read the version field and the source address one time, from the
    // start of the network header. The source is at offset 8 of the fixed
    // IPv6 header. Thus an extension header has no effect here.
    let mut hdr = [0u8; 24];
    let ret = unsafe {
        bpf_skb_load_bytes_relative(
            skb as *const c_void,
            0,
            hdr.as_mut_ptr() as *mut c_void,
            24,
            BPF_HDR_START_NET as u32,
        )
    };
    if ret != 0 || (hdr[0] >> 4) != 6 {
        count(ifindex, Field::OtherDropped);
        return Err(TC_ACT_SHOT as i32);
    }

    let mut saddr = [0u8; 16];
    saddr.copy_from_slice(&hdr[8..24]);

    // The per-cell anti-spoof check. `cell_source_allowed` is in
    // `aurae-ebpf-shared`, thus a host-side unit test can call it. A root
    // integration test is not the only test of this decision.
    if !cell_source_allowed(&saddr, &cfg.allowed_net, cfg.prefix_len) {
        count(ifindex, Field::SpoofDropped);
        return Err(TC_ACT_SHOT as i32);
    }

    // The host stack processes all other traffic. The nftables ruleset
    // decides there whether the packet is forwarded or dropped.
    count(ifindex, Field::Passed);
    Ok(TC_ACT_OK as i32)
}

enum Field {
    SpoofDropped,
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
            Field::Passed => stats.passed += 1,
            Field::OtherDropped => stats.other_dropped += 1,
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
