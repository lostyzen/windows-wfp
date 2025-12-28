//! WFP error types
//!
//! Error types for Windows Filtering Platform operations.

use thiserror::Error;
use windows::Win32::Foundation::WIN32_ERROR;

/// WFP operation errors
#[derive(Error, Debug)]
pub enum WfpError {
    /// Failed to open WFP engine session
    #[error("Failed to open WFP engine session")]
    EngineOpenFailed,

    /// Failed to close WFP engine session
    #[error("Failed to close WFP engine session")]
    EngineCloseFailed,

    /// Failed to add filter
    #[error("Failed to add filter: {0}")]
    FilterAddFailed(String),

    /// Failed to delete filter
    #[error("Failed to delete filter: {0}")]
    FilterDeleteFailed(String),

    /// Failed to begin transaction
    #[error("Failed to begin WFP transaction")]
    TransactionBeginFailed,

    /// Failed to commit transaction
    #[error("Failed to commit WFP transaction")]
    TransactionCommitFailed,

    /// Failed to abort transaction
    #[error("Failed to abort WFP transaction")]
    TransactionAbortFailed,

    /// Insufficient permissions (must run as administrator)
    #[error("Insufficient permissions - administrator privileges required")]
    InsufficientPermissions,

    /// WFP service not available
    #[error("Windows Filtering Platform service not available")]
    ServiceNotAvailable,

    /// Win32 API error with code and message
    #[error("Win32 error {code}: {message}")]
    Win32Error { code: u32, message: String },

    /// Generic error with description
    #[error("{0}")]
    Other(String),
}

impl From<WIN32_ERROR> for WfpError {
    fn from(error: WIN32_ERROR) -> Self {
        let code = error.0;
        let message = match code {
            5 => "Access denied".to_string(),
            1062 => "Service not started".to_string(),
            1075 => "Service dependency does not exist".to_string(),
            _ => format!("Unknown Win32 error: {}", code),
        };

        WfpError::Win32Error { code, message }
    }
}

pub type WfpResult<T> = std::result::Result<T, WfpError>;
