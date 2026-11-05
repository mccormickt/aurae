// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
#![no_std]
#![no_main]

use aurae_ebpf_shared::xdp::XdpNetConfig;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, XskMap},
    programs::XdpContext,
};

#[unsafe(link_section = "license")]
#[used]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[map]
static VM_CONFIG: HashMap<u32, XdpNetConfig> = HashMap::with_max_entries(2, 0);

#[map]
static VM_SOCKETS: XskMap = XskMap::with_max_entries(32, 0);

#[inline(always)]
fn header(ctx: &XdpContext) -> Option<*mut [u8; 54]> {
    if ctx.data() + 54 > ctx.data_end() {
        return None;
    }
    Some(ctx.data() as *mut [u8; 54])
}

#[xdp]
pub fn vm_transmit(ctx: XdpContext) -> u32 {
    let Some(header) = header(&ctx) else { return xdp_action::XDP_DROP };
    // SAFETY: the context and checked packet range remain live in this hook.
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let Some(config) = VM_CONFIG.get_ptr(&ifindex) else {
        return xdp_action::XDP_DROP;
    };
    // SAFETY: map values are kernel-owned and no packet helper invalidates data.
    if unsafe { (*config).permits_transmit(&*header) } {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    }
}

#[xdp]
pub fn vm_receive(ctx: XdpContext) -> u32 {
    let Some(header) = header(&ctx) else { return xdp_action::XDP_DROP };
    // SAFETY: the context remains live in this hook.
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let Some(config) = VM_CONFIG.get_ptr(&ifindex) else {
        return xdp_action::XDP_DROP;
    };
    // SAFETY: map and checked packet range remain live until redirect.
    let config = unsafe { &*config };
    let header = unsafe { &mut *header };
    if !config.permits_receive(header) {
        return xdp_action::XDP_DROP;
    }
    config.frame_for_guest(header);
    VM_SOCKETS
        .redirect(config.socket_key, u64::from(xdp_action::XDP_DROP))
        .unwrap_or(xdp_action::XDP_DROP)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
