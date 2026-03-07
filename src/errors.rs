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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        assert_eq!(
            WfpError::EngineOpenFailed.to_string(),
            "Failed to open WFP engine session"
        );
        assert_eq!(
            WfpError::InsufficientPermissions.to_string(),
            "Insufficient permissions - administrator privileges required"
        );
        assert_eq!(
            WfpError::ServiceNotAvailable.to_string(),
            "Windows Filtering Platform service not available"
        );
        assert_eq!(
            WfpError::TransactionBeginFailed.to_string(),
            "Failed to begin WFP transaction"
        );
        assert_eq!(
            WfpError::TransactionCommitFailed.to_string(),
            "Failed to commit WFP transaction"
        );
        assert_eq!(
            WfpError::TransactionAbortFailed.to_string(),
            "Failed to abort WFP transaction"
        );
    }

    #[test]
    fn test_error_display_with_details() {
        let err = WfpError::FilterAddFailed("test error".into());
        assert_eq!(err.to_string(), "Failed to add filter: test error");

        let err = WfpError::FilterDeleteFailed("filter 42".into());
        assert_eq!(err.to_string(), "Failed to delete filter: filter 42");

        let err = WfpError::Other("something happened".into());
        assert_eq!(err.to_string(), "something happened");
    }

    #[test]
    fn test_win32_error_display() {
        let err = WfpError::Win32Error {
            code: 5,
            message: "Access denied".into(),
        };
        assert_eq!(err.to_string(), "Win32 error 5: Access denied");
    }

    #[test]
    fn test_win32_error_conversion_access_denied() {
        let err: WfpError = WIN32_ERROR(5).into();
        match err {
            WfpError::Win32Error { code, message } => {
                assert_eq!(code, 5);
                assert_eq!(message, "Access denied");
            }
            _ => panic!("Expected Win32Error"),
        }
    }

    #[test]
    fn test_win32_error_conversion_service_not_started() {
        let err: WfpError = WIN32_ERROR(1062).into();
        match err {
            WfpError::Win32Error { code, message } => {
                assert_eq!(code, 1062);
                assert_eq!(message, "Service not started");
            }
            _ => panic!("Expected Win32Error"),
        }
    }

    #[test]
    fn test_win32_error_conversion_dependency_missing() {
        let err: WfpError = WIN32_ERROR(1075).into();
        match err {
            WfpError::Win32Error { code, message } => {
                assert_eq!(code, 1075);
                assert_eq!(message, "Service dependency does not exist");
            }
            _ => panic!("Expected Win32Error"),
        }
    }

    #[test]
    fn test_win32_error_conversion_unknown() {
        let err: WfpError = WIN32_ERROR(9999).into();
        match err {
            WfpError::Win32Error { code, message } => {
                assert_eq!(code, 9999);
                assert!(message.contains("Unknown"));
            }
            _ => panic!("Expected Win32Error"),
        }
    }
}
