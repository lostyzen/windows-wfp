//! WFP error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WfpError {
    #[error("WFP engine error: {0}")]
    EngineError(String),

    #[error("Filter creation failed: {0}")]
    FilterCreationFailed(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Win32 error {code}: {message}")]
    Win32Error { code: u32, message: String },
}

pub type WfpResult<T> = std::result::Result<T, WfpError>;
