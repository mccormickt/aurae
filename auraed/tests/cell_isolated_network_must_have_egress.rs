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
//! Integration test for cell network isolation. It proves that a cell
//! cannot reach the host or a live sibling, checks external IPv6 egress
//! when the host provides it, and confirms exact IPAM block reuse after
//! free.
//!
//! The test has an `#[ignore]` attribute and skips if the user is not root.
//! The creation of an interface pair, the installation of the nft rules,
//! and the open of a netns all need CAP_NET_ADMIN.

use client::cells::cell_service::CellServiceClient;
use common::cells::{
    CellServiceAllocateRequestBuilder, CellServiceStartRequestBuilder,
};
use proto::cells::{CellServiceFreeRequest, CellServiceStopRequest};
use std::path::Path;
use std::time::Duration;
use test_helpers::*;

mod common;

#[test_helpers_macros::shared_runtime_test]
#[ignore]
async fn cell_isolated_network_enforces_boundaries_and_has_egress() {
    skip_if_not_root!("cell_isolated_network_must_have_egress");
    skip_if_seccomp!("cell_isolated_network_must_have_egress");

    let client = common::auraed_client().await;

    // Allocate a cell with `isolate_network` set.
    let alloc_req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let cell_name = retry!(client.allocate(alloc_req.clone()).await)
        .expect("allocate cell with isolate_network=true")
        .into_inner()
        .cell_name;

    // The gateway is the host endpoint, but host-local services are outside
    // the cell boundary. Prove that the ping fails by writing a sentinel
    // only on its failure, then keep the command alive until `stop`.
    let blocked_path = std::env::temp_dir()
        .join(format!("aurae-host-blocked-{}", uuid::Uuid::new_v4()));
    let gw_v6_exec_name = format!("blocked-gw-v6-{}", uuid::Uuid::new_v4());
    let gw_v6_req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name(gw_v6_exec_name.clone())
        .command(format!(
            "if ping -6 -c 1 -W 2 fd00:ae::1; then exit 1; \
             else printf blocked > {}; sleep 30; fi",
            blocked_path.display()
        ))
        .build();
    retry!(client.start(gw_v6_req.clone()).await)
        .expect("start host-boundary probe");
    wait_for_nonempty_file(&blocked_path, Duration::from_secs(10)).await;

    retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: gw_v6_exec_name.clone(),
            })
            .await
    )
    .expect("stop host-boundary probe");

    // Record the exact endpoint identity before free. A later allocation
    // must receive the released block rather than merely another free slot.
    let first_addr_path = std::env::temp_dir()
        .join(format!("aurae-first-address-{}", uuid::Uuid::new_v4()));
    let first_addr_exec = format!("first-address-{}", uuid::Uuid::new_v4());
    let first_addr_req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name(first_addr_exec.clone())
        .command(format!(
            "ip -6 -o addr show dev eth0 scope global | awk '{{print $4}}' \
             > {} && test -s {} && sleep 30",
            first_addr_path.display(),
            first_addr_path.display()
        ))
        .build();
    retry!(client.start(first_addr_req.clone()).await)
        .expect("record first cell address");
    wait_for_nonempty_file(&first_addr_path, Duration::from_secs(10)).await;
    retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: first_addr_exec.clone(),
            })
            .await
    )
    .expect("stop first address probe");
    let first_addr = std::fs::read_to_string(&first_addr_path)
        .expect("read first address")
        .trim()
        .to_string();

    // Allocate a live sibling, record its address, and prove that the first
    // cell cannot reach it. Both addresses are in the shared host pool, so
    // this specifically exercises the interface-to-interface drop rather
    // than route absence.
    let sibling_req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let sibling_name = retry!(client.allocate(sibling_req.clone()).await)
        .expect("allocate sibling cell")
        .into_inner()
        .cell_name;
    let sibling_addr_path = std::env::temp_dir()
        .join(format!("aurae-sibling-address-{}", uuid::Uuid::new_v4()));
    let sibling_addr_exec = format!("sibling-address-{}", uuid::Uuid::new_v4());
    let sibling_addr_req = CellServiceStartRequestBuilder::new()
        .cell_name(sibling_name.clone())
        .executable_name(sibling_addr_exec.clone())
        .command(format!(
            "ip -6 -o addr show dev eth0 scope global | awk '{{print $4}}' \
             > {} && test -s {} && sleep 30",
            sibling_addr_path.display(),
            sibling_addr_path.display()
        ))
        .build();
    retry!(client.start(sibling_addr_req.clone()).await)
        .expect("record sibling address");
    wait_for_nonempty_file(&sibling_addr_path, Duration::from_secs(10)).await;
    retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(sibling_name.clone()),
                executable_name: sibling_addr_exec.clone(),
            })
            .await
    )
    .expect("stop sibling address probe");
    let sibling_addr = std::fs::read_to_string(&sibling_addr_path)
        .expect("read sibling address")
        .trim()
        .to_string();
    assert_ne!(first_addr, sibling_addr, "live cells need distinct blocks");

    let sibling_blocked_path = std::env::temp_dir()
        .join(format!("aurae-sibling-blocked-{}", uuid::Uuid::new_v4()));
    let sibling_probe_exec =
        format!("blocked-sibling-{}", uuid::Uuid::new_v4());
    let sibling_probe_req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name(sibling_probe_exec.clone())
        .command(format!(
            "if ping -6 -c 1 -W 2 {}; then exit 1; \
             else printf blocked > {}; sleep 30; fi",
            sibling_addr.trim_end_matches("/128"),
            sibling_blocked_path.display()
        ))
        .build();
    retry!(client.start(sibling_probe_req.clone()).await)
        .expect("start sibling-boundary probe");
    wait_for_nonempty_file(&sibling_blocked_path, Duration::from_secs(10))
        .await;
    retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: sibling_probe_exec.clone(),
            })
            .await
    )
    .expect("stop sibling-boundary probe");

    // Check the egress. Skip this step on a host without a v6 WAN.
    if has_host_v6_egress() {
        let egress_path = std::env::temp_dir()
            .join(format!("aurae-egress-ok-{}", uuid::Uuid::new_v4()));
        let exec_name = format!("ping-cf6-{}", uuid::Uuid::new_v4());
        let req = CellServiceStartRequestBuilder::new()
            .cell_name(cell_name.clone())
            .executable_name(exec_name.clone())
            .command(format!(
                "ping -6 -c 2 -W 5 2606:4700:4700::1111 && \
                 printf egress > {} && sleep 30",
                egress_path.display()
            ))
            .build();
        retry!(client.start(req.clone()).await)
            .expect("ping cloudflare v6 egress");
        wait_for_nonempty_file(&egress_path, Duration::from_secs(15)).await;
        retry!(
            client
                .stop(CellServiceStopRequest {
                    cell_name: Some(cell_name.clone()),
                    executable_name: exec_name.clone(),
                })
                .await
        )
        .expect("stop egress probe");
        let _ = std::fs::remove_file(egress_path);
    }

    // Free the cell. The IPAM slot must become available again.
    retry!(
        client
            .free(CellServiceFreeRequest { cell_name: cell_name.clone() })
            .await
    )
    .expect("free cell");

    // Allocate again and observe the endpoint identity. The released block
    // is the allocator's next reuse candidate.
    let realloc_req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let realloc_name = retry!(client.allocate(realloc_req.clone()).await)
        .expect("re-allocate after free")
        .into_inner()
        .cell_name;

    let second_addr_path = std::env::temp_dir()
        .join(format!("aurae-second-address-{}", uuid::Uuid::new_v4()));
    let second_addr_exec = format!("second-address-{}", uuid::Uuid::new_v4());
    let second_addr_req = CellServiceStartRequestBuilder::new()
        .cell_name(realloc_name.clone())
        .executable_name(second_addr_exec.clone())
        .command(format!(
            "ip -6 -o addr show dev eth0 scope global | awk '{{print $4}}' \
             > {} && test -s {} && sleep 30",
            second_addr_path.display(),
            second_addr_path.display()
        ))
        .build();
    retry!(client.start(second_addr_req.clone()).await)
        .expect("record reallocated cell address");
    wait_for_nonempty_file(&second_addr_path, Duration::from_secs(10)).await;
    retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(realloc_name.clone()),
                executable_name: second_addr_exec.clone(),
            })
            .await
    )
    .expect("stop second address probe");
    let second_addr = std::fs::read_to_string(&second_addr_path)
        .expect("read second address")
        .trim()
        .to_string();
    assert_eq!(second_addr, first_addr, "free must return the IPAM block");

    retry!(
        client
            .free(CellServiceFreeRequest { cell_name: realloc_name.clone() })
            .await
    )
    .expect("free re-allocated cell");

    retry!(
        client
            .free(CellServiceFreeRequest { cell_name: sibling_name.clone() })
            .await
    )
    .expect("free sibling cell");

    for path in [
        blocked_path,
        first_addr_path,
        sibling_addr_path,
        sibling_blocked_path,
        second_addr_path,
    ] {
        let _ = std::fs::remove_file(path);
    }
}

async fn wait_for_nonempty_file(path: &Path, timeout: Duration) {
    let started = tokio::time::Instant::now();
    loop {
        if path.metadata().map(|metadata| metadata.len() > 0).unwrap_or(false) {
            return;
        }
        assert!(
            started.elapsed() < timeout,
            "timed out waiting for successful probe at {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn has_host_v6_egress() -> bool {
    std::process::Command::new("ping")
        .args(["-6", "-c", "1", "-W", "2", "2606:4700:4700::1111"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
