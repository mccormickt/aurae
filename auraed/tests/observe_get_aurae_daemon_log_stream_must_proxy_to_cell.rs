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
    cells::CellServiceStopRequest, observe::GetAuraeDaemonLogStreamRequest,
};
use std::time::Duration;
use test_helpers::*;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn observe_get_aurae_daemon_log_stream_must_proxy_to_cell_when_cell_name_set()
 {
    skip_if_not_root!(
        "observe_get_aurae_daemon_log_stream_must_proxy_to_cell_when_cell_name_set"
    );
    skip_if_seccomp!(
        "observe_get_aurae_daemon_log_stream_must_proxy_to_cell_when_cell_name_set"
    );

    let client = common::auraed_client().await;

    // Allocate a cell so a nested auraed is running and addressable.
    let cell_name = retry!(
        client.allocate(CellServiceAllocateRequestBuilder::new().build()).await
    )
    .expect("allocate cell")
    .into_inner()
    .cell_name;

    // Subscribe to the nested daemon's tracing log stream from the host with
    // cell_name set — exercises the proxy path through CellService's
    // observe-trait impl.
    let mut stream = retry!(
        client
            .get_aurae_daemon_log_stream(GetAuraeDaemonLogStreamRequest {
                cell_name: Some(cell_name.clone()),
            })
            .await
    )
    .expect("get_aurae_daemon_log_stream proxies to nested daemon")
    .into_inner();

    // Trigger the nested daemon to emit tracing events by starting an
    // executable inside the cell. The nested `start` handler is heavily
    // instrumented (info!, instrument span entry/exit), so this guarantees
    // log lines.
    let exe_name = format!("ae-e2e-{}", uuid::Uuid::new_v4());
    let _pid = retry!(
        client
            .start(
                CellServiceStartRequestBuilder::new()
                    .cell_name(cell_name.clone())
                    .executable_name(exe_name.clone())
                    .build(),
            )
            .await
    )
    .expect("start executable in cell")
    .into_inner()
    .pid;

    // Read at least one tracing event line.
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
    .expect("did not receive any daemon log line within timeout");

    // Tracing-subscriber JSON layer emits one JSON object per event; we
    // only care that *something* came through the proxy.
    assert!(
        !line.trim().is_empty(),
        "expected non-empty tracing event line, got: {line:?}"
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
