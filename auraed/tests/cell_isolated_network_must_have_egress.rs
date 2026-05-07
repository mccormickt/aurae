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
//! Integration test for cell network isolation. Allocates a cell with
//! `isolate_network=true`, verifies it can ping the per-cell host gateway
//! (validates the in-cell endpoint setup) and external addresses
//! (validates host nft NAT egress), then frees the cell and confirms the
//! IPAM slot is reusable.
//!
//! `#[ignore]`-gated and skip-if-not-root because creating interface pairs +
//! installing nft rules + opening netnses requires CAP_NET_ADMIN.

use client::cells::cell_service::CellServiceClient;
use common::cells::{
    CellServiceAllocateRequestBuilder, CellServiceStartRequestBuilder,
};
use proto::cells::{CellServiceFreeRequest, CellServiceStopRequest};
use test_helpers::*;

mod common;

#[test_helpers_macros::shared_runtime_test]
#[ignore]
async fn cell_isolated_network_must_have_egress() {
    skip_if_not_root!("cell_isolated_network_must_have_egress");
    skip_if_seccomp!("cell_isolated_network_must_have_egress");

    let client = common::auraed_client().await;

    // Allocate a cell with isolate_network=true.
    let alloc_req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let cell_name = retry!(client.allocate(alloc_req.clone()).await)
        .expect("allocate cell with isolate_network=true")
        .into_inner()
        .cell_name;

    // Ping the cell-side host gateway (pool_base + 1).
    // Default pool: fd00:ae::/64 → gw fd00:ae::1.
    let gw_v6_exec_name = format!("ping-gw-v6-{}", uuid::Uuid::new_v4());
    let gw_v6_req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name(gw_v6_exec_name.clone())
        .build();
    // We can't easily set command via the builder, so swap by hand.
    let gw_v6_req = override_command(gw_v6_req, "ping -6 -c 2 -W 3 fd00:ae::1");
    retry!(client.start(gw_v6_req.clone()).await).expect("ping v6 gateway");

    let _ = retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: gw_v6_exec_name.clone(),
            })
            .await
    );

    // Best-effort egress check. Skipped on hosts without WAN v6.
    if has_host_v6_egress() {
        let exec_name = format!("ping-cf6-{}", uuid::Uuid::new_v4());
        let req = CellServiceStartRequestBuilder::new()
            .cell_name(cell_name.clone())
            .executable_name(exec_name.clone())
            .build();
        let req =
            override_command(req, "ping -6 -c 2 -W 5 2606:4700:4700::1111");
        retry!(client.start(req.clone()).await)
            .expect("ping cloudflare v6 egress");
        let _ = retry!(
            client
                .stop(CellServiceStopRequest {
                    cell_name: Some(cell_name.clone()),
                    executable_name: exec_name.clone(),
                })
                .await
        );
    }

    // Free the cell; the IPAM slot should become reusable.
    retry!(
        client
            .free(CellServiceFreeRequest { cell_name: cell_name.clone() })
            .await
    )
    .expect("free cell");

    // Re-allocate; succeeds even though we just released.
    let realloc_req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let realloc_name = retry!(client.allocate(realloc_req.clone()).await)
        .expect("re-allocate after free")
        .into_inner()
        .cell_name;

    retry!(
        client
            .free(CellServiceFreeRequest { cell_name: realloc_name.clone() })
            .await
    )
    .expect("free re-allocated cell");
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

fn has_host_v6_egress() -> bool {
    std::process::Command::new("ping")
        .args(["-6", "-c", "1", "-W", "2", "2606:4700:4700::1111"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
