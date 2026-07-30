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
//! cells with an isolated network. It then shows three properties of the
//! guard:
//!
//! 1. The guard passes traffic with a valid source to the host stack and
//!    counts it. The nftables policy still drops the cell-to-cell traffic.
//!    Thus the guard does not change the policy of
//!    `cell_isolated_network_must_have_egress`.
//! 2. The guard drops traffic with a source outside the delegated prefix of
//!    the cell and counts it.
//! 3. A free of the cell removes the config and stats entries of the cell.
//!
//! The assertions read the maps of the guard directly. The test daemon runs
//! in this process, and `aya::maps::loaded_maps` finds the maps by name.
//! The test asserts on the counters with a deadline and not on an exit
//! status, because `CellService::start` returns at the spawn.
//!
//! This test has two more requirements than the other isolated-network
//! test. The guard object must be installed with `make ebpf`, and the
//! kernel must support netkit and tcx, thus version 6.7 or later. Without
//! the guard the daemon falls back to nft. Then this test finds no map
//! entry for the cell and fails, because a fallback is not a pass.

use aurae_ebpf_shared::{CellNetConfig, CellNetStats};
use aya::maps::{
    HashMap as BpfHashMap, Map, MapData, PerCpuHashMap, loaded_maps,
};
use client::Client;
use client::cells::cell_service::CellServiceClient;
use common::cells::{
    CellServiceAllocateRequestBuilder, CellServiceStartRequestBuilder,
};
use proto::cells::{CellServiceFreeRequest, CellServiceStopRequest};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::path::Path;
use std::time::{Duration, Instant};
use test_helpers::*;

mod common;

const POLL_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_EVERY: Duration = Duration::from_millis(250);

/// A guarded cell: the ifindex of its netkit primary, which keys the maps,
/// and its address from `CELL_CONFIG`.
struct GuardedCell {
    name: String,
    ifindex: u32,
    ip: Ipv6Addr,
}

#[test_helpers_macros::shared_runtime_test]
#[ignore]
async fn cell_isolated_network_guard_must_count_and_block_spoof() {
    skip_if_not_root!("cell_isolated_network_guard_must_count_and_block_spoof");
    skip_if_seccomp!("cell_isolated_network_guard_must_count_and_block_spoof");

    let client = common::auraed_client().await;

    let cell_a = allocate_guarded_cell(&client).await;
    let cell_b = allocate_guarded_cell(&client).await;
    assert_ne!(cell_a.ip, cell_b.ip, "live cells need distinct addresses");

    let stats_map = find_stats_map(cell_a.ifindex)
        .expect("no CELL_STATS map contains the ifindex of cell A");
    assert!(
        stats_sum(stats_map, cell_b.ifindex).is_some(),
        "cells landed in different CELL_STATS maps; multiple guarded \
         daemons running?"
    );
    let base_a = stats_sum(stats_map, cell_a.ifindex).expect("cell A stats");

    // Cell A pings cell B. The guard accepts the source of A and counts the
    // echo requests in `passed`. The nft forward chain then drops them,
    // thus the ping fails and the probe writes the sentinel. Both results
    // together show that the guard makes no forwarding decision.
    let blocked_path = std::env::temp_dir()
        .join(format!("aurae-guard-sibling-blocked-{}", uuid::Uuid::new_v4()));
    let exec_name = format!("ping-cell-b-{}", uuid::Uuid::new_v4());
    let req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_a.name.clone())
        .executable_name(exec_name.clone())
        .command(format!(
            "if ping -6 -c 3 -W 2 {}; then exit 1; \
             else printf blocked > {}; sleep 30; fi",
            cell_b.ip,
            blocked_path.display()
        ))
        .build();
    retry!(client.start(req.clone()).await).expect("start cell-to-cell ping");

    wait_for_nonempty_file(&blocked_path, Duration::from_secs(15)).await;
    poll_until(
        "the guard to count the cell-to-cell pings (A.passed >= +3)",
        || {
            let a = stats_sum(stats_map, cell_a.ifindex).unwrap_or_default();
            a.passed >= base_a.passed + 3
        },
    )
    .await;

    let _ = retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_a.name.clone()),
                executable_name: exec_name.clone(),
            })
            .await
    );

    // Spoof test: add an address to cell A that is in the pool but belongs
    // to no cell, then send pings from it to cell B. The guard must drop
    // the packets before the host stack, thus `passed` does not increase.
    // The count is a minimum, because the kernel can send MLD reports for
    // the new address, and those have a source outside the prefix too.
    let spoof_base = stats_sum(stats_map, cell_a.ifindex)
        .expect("cell A stats before spoof");
    let exec_name = format!("spoof-{}", uuid::Uuid::new_v4());
    let req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_a.name.clone())
        .executable_name(exec_name.clone())
        .command(format!(
            "ip -6 addr add fd00:ae::dead/128 dev eth0 && \
             ping -6 -c 2 -W 1 -I fd00:ae::dead {}",
            cell_b.ip
        ))
        .build();
    retry!(client.start(req.clone()).await).expect("start spoofed pings");

    poll_until(
        "the guard to drop the spoofed pings (spoof_dropped >= +2)",
        || {
            let a = stats_sum(stats_map, cell_a.ifindex).unwrap_or_default();
            a.spoof_dropped >= spoof_base.spoof_dropped + 2
        },
    )
    .await;
    let after_spoof =
        stats_sum(stats_map, cell_a.ifindex).expect("cell A stats after spoof");
    assert_eq!(
        after_spoof.passed, spoof_base.passed,
        "a spoofed packet must not reach the host stack"
    );

    let _ = retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_a.name.clone()),
                executable_name: exec_name.clone(),
            })
            .await
    );

    // Free both cells. The destroy path must remove the config and stats
    // entries of each cell.
    for cell in [&cell_a, &cell_b] {
        retry!(
            client
                .free(CellServiceFreeRequest { cell_name: cell.name.clone() })
                .await
        )
        .expect("free cell");
    }
    poll_until("the BPF entries of the freed cells to be removed", || {
        [cell_a.ifindex, cell_b.ifindex].iter().all(|ifindex| {
            !map_contains_config(*ifindex) && !map_contains_stats(*ifindex)
        })
    })
    .await;

    let _ = std::fs::remove_file(&blocked_path);
}

/// Allocate a cell with an isolated network and find its guard entry. The
/// function compares the keys of each `CELL_CONFIG` map on the host before
/// and after the allocation. The address of the cell is the network
/// address of its delegated prefix.
async fn allocate_guarded_cell(client: &Client) -> GuardedCell {
    let before: Vec<(u32, HashSet<u32>)> = map_ids("CELL_CONFIG")
        .into_iter()
        .map(|id| (id, config_keys(id)))
        .collect();

    let req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let name = retry!(client.allocate(req.clone()).await)
        .expect("allocate cell with isolate_network=true")
        .into_inner()
        .cell_name;

    // List the map IDs again, because the maps of the daemon can be absent
    // at the time of the first snapshot. Exactly one map receives the entry
    // of this cell.
    for id in map_ids("CELL_CONFIG") {
        let baseline = before
            .iter()
            .find(|(before_id, _)| *before_id == id)
            .map(|(_, keys)| keys.clone())
            .unwrap_or_default();
        let Some(ifindex) =
            config_keys(id).difference(&baseline).next().copied()
        else {
            continue;
        };
        let cfg = config_entry(id, ifindex).expect("new CELL_CONFIG entry");
        return GuardedCell {
            name,
            ifindex,
            ip: Ipv6Addr::from(cfg.allowed_net),
        };
    }
    panic!(
        "allocating {name} added no CELL_CONFIG entry. The cell was created \
         in nft fallback mode. This test requires `make ebpf` and a kernel \
         with netkit and tcx; check the guard-mode log of the daemon."
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

fn config_map(map_id: u32) -> Option<BpfHashMap<MapData, u32, CellNetConfig>> {
    let data = MapData::from_id(map_id).ok()?;
    BpfHashMap::try_from(Map::HashMap(data)).ok()
}

/// Read the keys of a `CELL_CONFIG` map. An absent map gives an empty
/// result. The callers compare two snapshots, thus a temporary failure only
/// delays them.
fn config_keys(map_id: u32) -> HashSet<u32> {
    config_map(map_id)
        .map(|map| map.keys().filter_map(|key| key.ok()).collect())
        .unwrap_or_default()
}

fn config_entry(map_id: u32, ifindex: u32) -> Option<CellNetConfig> {
    config_map(map_id)?.get(&ifindex, 0).ok()
}

fn map_contains_config(ifindex: u32) -> bool {
    map_ids("CELL_CONFIG")
        .into_iter()
        .any(|map_id| config_entry(map_id, ifindex).is_some())
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
        total.passed += v.passed;
        total.other_dropped += v.other_dropped;
    }
    Some(total)
}

fn map_contains_stats(ifindex: u32) -> bool {
    map_ids("CELL_STATS")
        .into_iter()
        .any(|map_id| stats_sum(map_id, ifindex).is_some())
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

async fn wait_for_nonempty_file(path: &Path, timeout: Duration) {
    let started = tokio::time::Instant::now();
    loop {
        if path.metadata().map(|metadata| metadata.len() > 0).unwrap_or(false) {
            return;
        }
        assert!(
            started.elapsed() < timeout,
            "timed out waiting for the probe sentinel at {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
