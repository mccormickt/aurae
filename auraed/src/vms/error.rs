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

use thiserror::Error;
use tonic::Status;
use tracing::error;

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
    #[error("vm '{id}' has invalid network configuration: {message}")]
    InvalidNetworkConfig { id: VmID, message: String },
}

impl From<VmServiceError> for Status {
    fn from(err: VmServiceError) -> Self {
        let msg = err.to_string();
        error!("{msg}");
        match err {
            VmServiceError::FailedToAllocateError { .. }
            | VmServiceError::FailedToFreeError { .. }
            | VmServiceError::FailedToStartError { .. }
            | VmServiceError::FailedToStopError { .. } => Status::internal(msg),
            VmServiceError::MissingMachineConfig => {
                Status::failed_precondition(msg)
            }
            VmServiceError::InvalidNetworkConfig { .. } => {
                Status::invalid_argument(msg)
            }
        }
    }
}
