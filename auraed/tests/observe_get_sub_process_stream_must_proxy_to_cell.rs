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
use client::{
    cells::cell_service::CellServiceClient,
    observe::observe_service::ObserveServiceClient,
};
use common::cells::{
    CellServiceAllocateRequestBuilder, CellServiceStartRequestBuilder,
};
use proto::{
    cells::CellServiceStopRequest,
    observe::{GetSubProcessStreamRequest, LogChannelType},
};
use std::time::Duration;
use test_helpers::*;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn observe_get_sub_process_stream_must_proxy_to_cell_when_cell_name_set()
{
    skip_if_not_root!(
        "observe_get_sub_process_stream_must_proxy_to_cell_when_cell_name_set"
    );
    skip_if_seccomp!(
        "observe_get_sub_process_stream_must_proxy_to_cell_when_cell_name_set"
    );

    let client = common::auraed_client().await;

    // Allocate a cell
    let cell_name = retry!(
        client.allocate(CellServiceAllocateRequestBuilder::new().build()).await
    )
    .expect("allocate cell")
    .into_inner()
    .cell_name;

    // Start a long-running executable that emits stdout. Use a sleep loop so
    // the subscribe wins the race against fast-finishing children.
    let exe_name = format!("ae-e2e-{}", uuid::Uuid::new_v4());
    let pid = retry!(
        client
            .start(
                CellServiceStartRequestBuilder::new()
                    .cell_name(cell_name.clone())
                    .executable_name(exe_name.clone())
                    .command(
                        "for i in 1 2 3 4 5 6 7 8 9 10; do echo line $i; sleep 1; done"
                            .into(),
                    )
                    .build(),
            )
            .await
    )
    .expect("start executable in cell")
    .into_inner()
    .pid;

    // Subscribe to the sub-process stream from the host with cell_name set —
    // exercises the proxy path through CellService's observe-trait impl.
    let mut stream = retry!(
        client
            .get_sub_process_stream(GetSubProcessStreamRequest {
                process_id: pid,
                channel_type: LogChannelType::Stdout as i32,
                cell_name: Some(cell_name.clone()),
            })
            .await
    )
    .expect("get_sub_process_stream proxies to nested daemon")
    .into_inner();

    // Read at least one stdout line.
    let line = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match futures_util::StreamExt::next(&mut stream).await {
                Some(Ok(resp)) => {
                    if let Some(item) = resp.item
                        && !item.line.is_empty()
                    {
                        break item.line;
                    }
                }
                Some(Err(e)) => panic!("stream returned error: {e:?}"),
                None => panic!("stream closed before any item"),
            }
        }
    })
    .await
    .expect("did not receive any stdout line within timeout");

    assert!(
        line.starts_with("line "),
        "expected stdout line to start with 'line ', got: {line:?}"
    );

    // Clean up the executable.
    let _ = retry!(
        client
            .stop(CellServiceStopRequest {
                cell_name: Some(cell_name.clone()),
                executable_name: exe_name.clone(),
            })
            .await
    );
}
