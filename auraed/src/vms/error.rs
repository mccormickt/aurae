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

use client::ClientError;
use thiserror::Error;
use tonic::Status;
use tracing::error;
use validation::ValidationError;

use crate::cells::cell_service::cells::CellsError;

use super::virtual_machine::VmID;

pub(crate) type Result<T> = std::result::Result<T, VmServiceError>;

#[derive(Debug, Error)]
pub(crate) enum VmServiceError {
    #[error("vm '{id}' could not be allocated: {source}")]
    FailedToAllocateError { id: VmID, source: anyhow::Error },
    #[error("vm '{id}' could not be freed: {source}")]
    FailedToFreeError { id: VmID, source: anyhow::Error },
    #[error("vm '{id}' could not be started: {source}")]
    FailedToStartError { id: VmID, source: anyhow::Error },
    #[error("vm '{id}' could not be stopped: {source}")]
    FailedToStopError { id: VmID, source: anyhow::Error },
    #[error("vm config has no machine specified")]
    MissingMachineConfig,
    #[error("vm '{id}' config has no root drive specified")]
    MissingRootDrive { id: VmID },
    #[error(
        "vm networking is unavailable on this host (forwarding could not be \
         enabled or netlink failed); see daemon logs for details"
    )]
    NetworkingUnavailable,

    /// A local (non-proxied) VM lifecycle RPC reached an auraed that isn't
    /// the host daemon — i.e. a nested auraed inside a cell. The host
    /// proxies `cell_name`-scoped requests here, but a nested auraed can't
    /// host VMs itself yet: it has no `Network`/IPAM of its own (prefix
    /// delegation for nested allocation isn't wired). Distinct from
    /// [`Self::NetworkingUnavailable`], which is a genuine host-side
    /// networking failure.
    #[error(
        "virtual machines cannot be managed inside a cell yet: this auraed \
         is nested, not the host daemon"
    )]
    VmInCellUnsupported,

    /// `cell_name` field on the request was syntactically invalid.
    #[error("invalid cell_name: {source}")]
    InvalidCellName {
        #[source]
        source: ValidationError,
    },

    /// Proxy target lookup failed: cell not in cache, or not allocated.
    #[error("cell '{cell_name}' not found or not allocated: {source}")]
    VmCellNotFound { cell_name: String, source: CellsError },

    /// Proxy connect failed (e.g. nested auraed unix socket not yet up).
    #[error(
        "could not connect to nested auraed in cell '{cell_name}': {source}"
    )]
    VmCellUnavailable { cell_name: String, source: ClientError },

    /// Proxy succeeded; the nested auraed returned this `Status`. Pass it
    /// through unchanged so callers see the same code+message they'd see
    /// from a direct call.
    #[error("{0}")]
    ProxiedStatus(Status),
}

impl From<VmServiceError> for Status {
    fn from(err: VmServiceError) -> Self {
        // Proxied errors pass through unchanged. The source daemon already
        // logged + assigned a Status code; re-wrapping it here would just
        // double-log and lose the original code category.
        if let VmServiceError::ProxiedStatus(status) = err {
            return status;
        }

        let msg = err.to_string();
        error!("{msg}");
        match err {
            VmServiceError::FailedToAllocateError { .. }
            | VmServiceError::FailedToFreeError { .. }
            | VmServiceError::FailedToStartError { .. }
            | VmServiceError::FailedToStopError { .. } => Status::internal(msg),
            VmServiceError::MissingMachineConfig
            | VmServiceError::MissingRootDrive { .. }
            | VmServiceError::NetworkingUnavailable => {
                Status::failed_precondition(msg)
            }
            VmServiceError::VmInCellUnsupported => Status::unimplemented(msg),
            VmServiceError::InvalidCellName { .. } => {
                Status::invalid_argument(msg)
            }
            VmServiceError::VmCellNotFound { .. } => Status::not_found(msg),
            VmServiceError::VmCellUnavailable { .. } => {
                Status::unavailable(msg)
            }
            // Already handled above; the early-return makes this unreachable.
            VmServiceError::ProxiedStatus(_) => unreachable!(),
        }
    }
}
