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
 * Copyright 2022 - 2026, the aurae contributors                              *
 * SPDX-License-Identifier: Apache-2.0                                        *
\* -------------------------------------------------------------------------- */
//! Integration test for the cell-net BPF guard: allocates two
//! network-isolated cells, proves cell→cell traffic takes the
//! `bpf_redirect_peer` fast path (via the guard's per-cell counters —
//! the host stack would happily forward the same ping, so only the
//! counters distinguish the datapath), and proves per-cell anti-spoof
//! by sourcing pings from an in-pool-but-unassigned address, which the
//! pool-granularity nftables rule would have passed.
//!
//! Assertions read the guard's maps directly (the test daemon runs in
//! this process; `aya::maps::loaded_maps` finds them by name). Command
//! outcomes are asserted via counters with a deadline, never via exit
//! status — `CellService::start` returns at spawn time.
//!
//! Requirements beyond the other isolated-network test: the guard
//! object must be installed (`make ebpf`) and the kernel must support
//! netkit + tcx (>= 6.7). The test fails loudly — not silently green —
//! when the daemon degraded to guard-less operation.

use aurae_ebpf_shared::CellNetStats;
use aya::maps::lpm_trie::LpmTrie;
use aya::maps::{Map, MapData, PerCpuHashMap, loaded_maps};
use client::Client;
use client::cells::cell_service::CellServiceClient;
use common::cells::{
    CellServiceAllocateRequestBuilder, CellServiceStartRequestBuilder,
};
use proto::cells::{CellServiceFreeRequest, CellServiceStopRequest};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};
use test_helpers::*;

mod common;

/// `(address bytes, prefix length, primary ifindex)` from `CELL_REDIRECT`.
type RedirectEntry = ([u8; 16], u32, u32);

const POLL_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_EVERY: Duration = Duration::from_millis(250);

#[test_helpers_macros::shared_runtime_test]
#[ignore]
async fn cell_isolated_network_must_redirect_cell_to_cell_and_block_spoof() {
    skip_if_not_root!(
        "cell_isolated_network_must_redirect_cell_to_cell_and_block_spoof"
    );
    skip_if_seccomp!(
        "cell_isolated_network_must_redirect_cell_to_cell_and_block_spoof"
    );

    let client = common::auraed_client().await;

    let (cell_a, a_entry, map_a) = allocate_isolated_cell(&client).await;
    let (cell_b, b_entry, map_b) = allocate_isolated_cell(&client).await;
    assert_eq!(
        map_a, map_b,
        "cells landed in different CELL_REDIRECT maps — multiple guarded \
         daemons running?"
    );
    let (_, _, a_ifindex) = a_entry;
    let (b_ip_bytes, _, b_ifindex) = b_entry;
    let b_ip = Ipv6Addr::from(b_ip_bytes);

    let stats_map = find_stats_map(a_ifindex)
        .expect("no CELL_STATS map contains cell A's ifindex");
    let base_a = stats_sum(stats_map, a_ifindex).expect("cell A stats");
    let base_b = stats_sum(stats_map, b_ifindex).expect("cell B stats");

    // Cell A pings cell B. A's `redirected` counter covers the echo
    // requests, B's covers the replies; host-stack forwarding would
    // tick neither.
    let exec_name = format!("ping-cell-b-{}", uuid::Uuid::new_v4());
    let req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_a.clone())
        .executable_name(exec_name.clone())
        .build();
    let req = override_command(req, &format!("ping -6 -c 3 -W 3 {b_ip}"));
    retry!(client.start(req.clone()).await).expect("start cell-to-cell ping");

    poll_until(
        "cell-to-cell pings to take the bpf_redirect_peer fast path \
         (A.redirected >= +3, B.redirected >= +1)",
        || {
            let a = stats_sum(stats_map, a_ifindex).unwrap_or_default();
            let b = stats_sum(stats_map, b_ifindex).unwrap_or_default();
            a.redirected >= base_a.redirected + 3
                && b.redirected > base_b.redirected
        },
    )
    .await;

    let _ = retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_a.clone()),
                executable_name: exec_name.clone(),
            })
            .await
    );

    // Spoof: add an in-pool-but-unassigned address inside cell A and
    // source pings from it toward the gateway and toward cell B. The
    // nftables anti-spoof rule only checks "saddr in pool" and would
    // pass these; the guard pins cell A to its delegated /128.
    let spoof_base =
        stats_sum(stats_map, a_ifindex).expect("cell A stats before spoof");
    let exec_name = format!("spoof-{}", uuid::Uuid::new_v4());
    let req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_a.clone())
        .executable_name(exec_name.clone())
        .build();
    let req = override_command(
        req,
        &format!(
            "ip -6 addr add fd00:ae::dead/128 dev eth0 && \
             ping -6 -c 2 -W 1 -I fd00:ae::dead fd00:ae::1; \
             ping -6 -c 2 -W 1 -I fd00:ae::dead {b_ip}"
        ),
    );
    retry!(client.start(req.clone()).await).expect("start spoofed pings");

    poll_until("spoofed packets to be dropped (spoof_dropped >= +2)", || {
        let a = stats_sum(stats_map, a_ifindex).unwrap_or_default();
        a.spoof_dropped >= spoof_base.spoof_dropped + 2
    })
    .await;
    let after_spoof =
        stats_sum(stats_map, a_ifindex).expect("cell A stats after spoof");
    assert_eq!(
        after_spoof.redirected, spoof_base.redirected,
        "spoofed packets must never reach the redirect fast path"
    );

    let _ = retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_a.clone()),
                executable_name: exec_name.clone(),
            })
            .await
    );

    // Free both cells; the destroy path must remove their map entries
    // (guard map hygiene — stale entries would shadow recycled
    // ifindexes).
    retry!(
        client.free(CellServiceFreeRequest { cell_name: cell_a.clone() }).await
    )
    .expect("free cell A");
    retry!(
        client.free(CellServiceFreeRequest { cell_name: cell_b.clone() }).await
    )
    .expect("free cell B");

    poll_until("freed cells' CELL_REDIRECT entries to be removed", || {
        let entries = redirect_entries(map_a);
        !entries.contains(&a_entry) && !entries.contains(&b_entry)
    })
    .await;
}

/// Allocate a network-isolated cell and identify its redirect entry by
/// diffing every `CELL_REDIRECT` map on the host across the allocation.
/// Returns `(cell_name, entry, map_id)`.
async fn allocate_isolated_cell(
    client: &Client,
) -> (String, RedirectEntry, u32) {
    let before: Vec<(u32, HashSet<RedirectEntry>)> = map_ids("CELL_REDIRECT")
        .into_iter()
        .map(|id| (id, redirect_entries(id)))
        .collect();

    let req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let cell_name = retry!(client.allocate(req.clone()).await)
        .expect("allocate cell with isolate_network=true")
        .into_inner()
        .cell_name;

    // Re-list map ids: the daemon's maps may not have existed at snapshot
    // time. Exactly one map gains exactly this cell's entry.
    for id in map_ids("CELL_REDIRECT") {
        let baseline = before
            .iter()
            .find(|(before_id, _)| *before_id == id)
            .map(|(_, entries)| entries.clone())
            .unwrap_or_default();
        if let Some(entry) =
            redirect_entries(id).difference(&baseline).next().copied()
        {
            return (cell_name, entry, id);
        }
    }
    panic!(
        "allocating {cell_name} added no CELL_REDIRECT entry — the daemon \
         is running without the cell-net BPF guard. Install the eBPF \
         programs with `make ebpf` (kernel >= 6.7 with netkit + tcx \
         required) and re-run."
    );
}

/// IDs of all loaded BPF maps with the given object name.
fn map_ids(name: &str) -> Vec<u32> {
    loaded_maps()
        .filter_map(|info| info.ok())
        .filter(|info| info.name_as_str() == Some(name))
        .map(|info| info.id())
        .collect()
}

/// Snapshot a `CELL_REDIRECT` map's entries. Missing/raced maps read as
/// empty — callers diff snapshots, so transient failures only delay them.
fn redirect_entries(map_id: u32) -> HashSet<RedirectEntry> {
    let Ok(data) = MapData::from_id(map_id) else {
        return HashSet::new();
    };
    let Ok(trie) =
        LpmTrie::<MapData, [u8; 16], u32>::try_from(Map::LpmTrie(data))
    else {
        return HashSet::new();
    };
    trie.iter()
        .filter_map(|entry| entry.ok())
        .map(|(key, ifindex)| (key.data(), key.prefix_len(), ifindex))
        .collect()
}

/// Sum a cell's per-CPU stats. `None` when the map has no entry for the
/// ifindex (also used to discover which `CELL_STATS` map is ours).
fn stats_sum(map_id: u32, ifindex: u32) -> Option<CellNetStats> {
    let data = MapData::from_id(map_id).ok()?;
    let map = PerCpuHashMap::<MapData, u32, CellNetStats>::try_from(
        Map::PerCpuHashMap(data),
    )
    .ok()?;
    let values = map.get(&ifindex, 0).ok()?;
    let mut total = CellNetStats::default();
    for v in values.iter() {
        total.spoof_dropped += v.spoof_dropped;
        total.redirected += v.redirected;
        total.passed += v.passed;
        total.other_dropped += v.other_dropped;
    }
    Some(total)
}

fn find_stats_map(ifindex: u32) -> Option<u32> {
    map_ids("CELL_STATS")
        .into_iter()
        .find(|id| stats_sum(*id, ifindex).is_some())
}

/// Poll `condition` until it holds or `POLL_TIMEOUT` elapses.
async fn poll_until(what: &str, condition: impl Fn() -> bool) {
    let start = Instant::now();
    while start.elapsed() < POLL_TIMEOUT {
        if condition() {
            return;
        }
        tokio::time::sleep(POLL_EVERY).await;
    }
    panic!("timed out after {POLL_TIMEOUT:?} waiting for {what}");
}

/// Replace the executable command on a freshly built start request. The
/// builder doesn't expose a `command` setter; rather than expand it for
/// one test, we patch the proto directly here.
fn override_command(
    mut req: proto::cells::CellServiceStartRequest,
    command: &str,
) -> proto::cells::CellServiceStartRequest {
    if let Some(exec) = req.executable.as_mut() {
        exec.command = command.to_string();
    }
    req
}
