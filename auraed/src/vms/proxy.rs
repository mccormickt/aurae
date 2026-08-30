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

//! Generic proxy of a `VmService` RPC into a nested auraed running inside a
//! cell. The body that used to be `do_in_vm_cell!` lives here as a regular
//! async fn — the per-RPC client method comes in as a closure rather than
//! being spliced via macro substitution.

use std::future::Future;
use std::time::Duration;

use backoff::backoff::Backoff;
use client::{Client, ClientError};
use tokio::sync::Mutex;
use tracing::trace;

use crate::cells::cell_service::cells::{CellName, Cells};

use super::error::{Result, VmServiceError};

/// Forward an RPC into the nested auraed inside `cell_name`.
///
/// 1. Look up the cell's client socket from `cells`. Lock is dropped before
///    the connect-with-retry loop so the cells map isn't held across
///    awaits.
/// 2. Open a unix-socket [`Client`] with exponential-backoff retry on
///    connection errors. Gives the nested auraed up to ~20s to come up.
/// 3. Call `call(client, request)` exactly once. A mutation may have reached
///    the nested daemon even when its response is lost, so retrying after
///    dispatch would make Allocate/Start/Stop/Free observably non-idempotent.
///
/// `request` should already have any cell-routing field cleared by the
/// caller — typically `request.cell_name = None` — so the receiving daemon
/// executes locally rather than re-proxying.
pub(crate) async fn proxy_to_cell<Req, Resp, Fut, F>(
    cells: &Mutex<Cells>,
    cell_name: &CellName,
    request: Req,
    call: F,
) -> Result<Resp>
where
    F: Fn(Client, Req) -> Fut,
    Fut: Future<Output = std::result::Result<Resp, tonic::Status>>,
{
    let (client_socket, control_token) = {
        let mut cells = cells.lock().await;
        cells.get(cell_name, |cell| cell.vm_control()).map_err(|e| {
            VmServiceError::VmCellNotFound {
                cell_name: cell_name.to_string(),
                source: e,
            }
        })?
    };

    let mut retry_strategy = backoff::ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_millis(50))
        .with_multiplier(10.0)
        .with_randomization_factor(0.5)
        .with_max_interval(Duration::from_secs(3))
        .with_max_elapsed_time(Some(Duration::from_secs(20)))
        .build();

    let client = loop {
        match Client::new_no_tls_with_vm_control_token(
            client_socket.clone(),
            control_token.expose_secret(),
        )
        .await
        {
            Ok(client) => break Ok(client),
            e @ Err(ClientError::ConnectionError(_)) => {
                trace!("aurae client failed to connect: {e:?}");
                if let Some(delay) = retry_strategy.next_backoff() {
                    trace!("retrying in {delay:?}");
                    tokio::time::sleep(delay).await
                } else {
                    break e;
                }
            }
            e => break e,
        }
    }
    .map_err(|e| VmServiceError::VmCellUnavailable {
        cell_name: cell_name.to_string(),
        source: e,
    })?;

    call(client, request).await.map_err(VmServiceError::ProxiedStatus)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `proxy_to_cell` returns `VmCellNotFound` synchronously if the
    /// target cell isn't in the cache — without ever touching `call`.
    #[tokio::test]
    async fn missing_cell_returns_not_found() {
        let cells = Mutex::new(Cells::new_root(None));
        let cell_name =
            <CellName as validation::ValidatedField<String>>::validate(
                Some("nope".to_string()),
                "cell_name",
                None,
            )
            .expect("valid cell name");

        let result: Result<()> =
            proxy_to_cell(&cells, &cell_name, (), |_client, _req| async move {
                panic!("call must not be invoked when cell lookup fails")
            })
            .await;

        assert!(matches!(result, Err(VmServiceError::VmCellNotFound { .. })));
    }
}
