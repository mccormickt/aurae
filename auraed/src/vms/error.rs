use thiserror::Error;
use tonic::Status;
use tracing::error;

use client::ClientError;

#[derive(Debug, Error)]
pub enum VmServiceError {
    #[error("vm '{vm_id}' already exists")]
    VmExists { vm_id: String },
    #[error("vm '{vm_id}' not found")]
    VmNotFound { vm_id: String },
    #[error("sandobx '{vm_id}' not in exited state")]
    VmNotExited { vm_id: String },
    #[error("Failed to kill vm '{vm_id}': {error}")]
    KillError { vm_id: String, error: String },
    #[error(transparent)]
    ClientError(#[from] ClientError),
}

impl From<VmServiceError> for Status {
    fn from(err: VmServiceError) -> Self {
        let msg = err.to_string();
        error!("{msg}");
        match err {
            VmServiceError::VmExists { .. } => Status::already_exists(msg),
            VmServiceError::VmNotFound { .. } => Status::not_found(msg),
            VmServiceError::VmNotExited { .. } => {
                Status::failed_precondition(msg)
            }
            VmServiceError::KillError { .. } => Status::internal(msg),
            VmServiceError::ClientError(e) => match e {
                ClientError::ConnectionError(_) => Status::unavailable(msg),
                ClientError::Other(_) => Status::unknown(msg),
            },
        }
    }
}
