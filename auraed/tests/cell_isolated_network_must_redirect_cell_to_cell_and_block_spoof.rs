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

//! Integration test for the cell-net BPF guard. The test allocates two
//! cells with an isolated network. It then shows that cell-to-cell traffic
//! uses the `bpf_redirect_peer` fast path. The per-cell counters of the
//! guard give that proof, because the host stack forwards the same ping and
//! only the counters show the datapath. The test also shows the per-cell
//! anti-spoof check. It sends pings from an address that is in the pool but
//! belongs to no cell.
//!
//! The assertions read the maps of the guard directly. The test daemon runs
//! in this process, and `aya::maps::loaded_maps` finds the maps by name.
//! The test asserts on the counters with a deadline and not on an exit
//! status, because `CellService::start` returns at the spawn.
//!
//! This test has two more requirements than the other isolated-network
//! test. The guard object must be installed with `make ebpf`, and the
//! kernel must support netkit and tcx, thus version 6.7 or later. Without
//! them the daemon refuses to allocate a cell with an isolated network, and
//! the allocation below fails.

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

/// One `CELL_REDIRECT` entry: the address bytes, the prefix length, and
/// the ifindex of the primary.
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

    // Cell A pings cell B. The `redirected` counter of A counts the echo
    // requests, and the counter of B counts the replies. A forward through
    // the host stack increases neither counter.
    let exec_name = format!("ping-cell-b-{}", uuid::Uuid::new_v4());
    let req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_a.clone())
        .executable_name(exec_name.clone())
        .command(format!("ping -6 -c 3 -W 3 {b_ip}"))
        .build();
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

    // Spoof test: add an address to cell A that is in the pool but belongs
    // to no cell, then send pings from it to the gateway and to cell B. The
    // guard binds cell A to its delegated /128 and must drop the pings.
    let spoof_base =
        stats_sum(stats_map, a_ifindex).expect("cell A stats before spoof");
    let exec_name = format!("spoof-{}", uuid::Uuid::new_v4());
    let req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_a.clone())
        .executable_name(exec_name.clone())
        .command(format!(
            "ip -6 addr add fd00:ae::dead/128 dev eth0 && \
             ping -6 -c 2 -W 1 -I fd00:ae::dead fd00:ae::1; \
             ping -6 -c 2 -W 1 -I fd00:ae::dead {b_ip}"
        ))
        .build();
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

    // Free both cells. The destroy path must remove their map entries. An
    // old entry would apply to a recycled ifindex.
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

/// Allocate a cell with an isolated network and find its redirect entry.
/// The function compares each `CELL_REDIRECT` map on the host before and
/// after the allocation. It returns the cell name, the entry, and the map
/// ID.
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

    // List the map IDs again, because the maps of the daemon can be absent
    // at the time of the first snapshot. Exactly one map receives the entry
    // of this cell.
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
        "allocating {cell_name} added no CELL_REDIRECT entry. The cell was \
         created, so the guard did load — the redirect entry is published \
         separately once the nested auraed reports ready, so this points at \
         `publish_cell_redirect` failing (check the daemon log) rather than \
         at a missing `make ebpf` install."
    );
}

/// The IDs of all loaded BPF maps with the given name.
fn map_ids(name: &str) -> Vec<u32> {
    loaded_maps()
        .filter_map(|info| info.ok())
        .filter(|info| info.name_as_str() == Some(name))
        .map(|info| info.id())
        .collect()
}

/// Read the entries of a `CELL_REDIRECT` map. An absent map gives an empty
/// result. The callers compare two snapshots, thus a temporary failure only
/// delays them.
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

/// Add the per-CPU stats of one cell. The function returns `None` if the
/// map has no entry for the ifindex. The test also uses this result to find
/// the correct `CELL_STATS` map.
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

/// Poll `condition` until it is true or `POLL_TIMEOUT` ends.
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
