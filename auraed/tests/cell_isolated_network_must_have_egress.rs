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
//! Integration test for the network isolation of a cell. The test
//! allocates a cell with `isolate_network=true`. It then pings the host
//! gateway of the cell, which shows a correct endpoint setup in the cell.
//! It also pings an external address, which shows a correct nft NAT egress
//! on the host. Then it frees the cell and confirms that the IPAM slot is
//! available again.
//!
//! The test has an `#[ignore]` attribute and skips if the user is not root.
//! The creation of an interface pair, the installation of the nft rules,
//! and the open of a netns all need CAP_NET_ADMIN.

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

    // Allocate a cell with `isolate_network` set.
    let alloc_req =
        CellServiceAllocateRequestBuilder::new().isolate_network().build();
    let cell_name = retry!(client.allocate(alloc_req.clone()).await)
        .expect("allocate cell with isolate_network=true")
        .into_inner()
        .cell_name;

    // Ping the host gateway at `pool_base + 1`. The default pool
    // fd00:ae::/64 gives the gateway fd00:ae::1.
    let gw_v6_exec_name = format!("ping-gw-v6-{}", uuid::Uuid::new_v4());
    let gw_v6_req = CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name(gw_v6_exec_name.clone())
        .command("ping -6 -c 2 -W 3 fd00:ae::1".into())
        .build();
    retry!(client.start(gw_v6_req.clone()).await).expect("ping v6 gateway");

    let _ = retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: gw_v6_exec_name.clone(),
            })
            .await
    );

    // Check the egress. Skip this step on a host without a v6 WAN.
    if has_host_v6_egress() {
        let exec_name = format!("ping-cf6-{}", uuid::Uuid::new_v4());
        let req = CellServiceStartRequestBuilder::new()
            .cell_name(cell_name.clone())
            .executable_name(exec_name.clone())
            .command("ping -6 -c 2 -W 5 2606:4700:4700::1111".into())
            .build();
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

    // Free the cell. The IPAM slot must become available again.
    retry!(
        client
            .free(CellServiceFreeRequest { cell_name: cell_name.clone() })
            .await
    )
    .expect("free cell");

    // Allocate again. This must be successful after the release.
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

fn has_host_v6_egress() -> bool {
    std::process::Command::new("ping")
        .args(["-6", "-c", "1", "-W", "2", "2606:4700:4700::1111"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
