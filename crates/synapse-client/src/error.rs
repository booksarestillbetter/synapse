//! Error types for the Synapse Client SDK.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SynapseClientError {
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC error ({code:?}): {message}")]
    Rpc {
        code: tonic::Code,
        message: String,
    },

    #[error("delta stream unexpectedly closed by server")]
    StreamClosed,

    #[error("invalid endpoint URL: {0}")]
    InvalidEndpoint(String),

    #[error("invalid info-hash format: {0}")]
    InvalidHash(String),

    #[error("operation timed out")]
    Timeout,
}

impl From<tonic::Status> for SynapseClientError {
    fn from(status: tonic::Status) -> Self {
        Self::Rpc {
            code: status.code(),
            message: status.message().to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, SynapseClientError>;
