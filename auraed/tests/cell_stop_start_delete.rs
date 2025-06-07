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
use client::cells::cell_service::CellServiceClient;
use test_helpers::*;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn cells_start_stop_delete() {
    skip_if_not_root!("cells_start_stop_delete");
    skip_if_seccomp!("cells_start_stop_delete");

    let client = common::auraed_client().await;

    // Allocate a cell
    let cell_name = retry!(
        client
            .allocate(
                common::cells::CellServiceAllocateRequestBuilder::new().build()
            )
            .await
    )
    .unwrap()
    .into_inner()
    .cell_name;

    // Start the executable
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .cell_name(cell_name.clone())
        .executable_name("aurae-exe".to_string())
        .build();
    let _ = retry!(client.start(req.clone()).await).unwrap().into_inner();

    // Stop the executable
    let _ = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: "aurae-exe".to_string(),
            })
            .await
    )
    .unwrap();

    // Delete the cell
    let _ = retry!(
        client
            .free(proto::cells::CellServiceFreeRequest {
                cell_name: cell_name.clone()
            })
            .await
    )
    .unwrap();
}
