//! WFP error types
//!
//! Error types for Windows Filtering Platform operations.

use thiserror::Error;
use windows::core::HRESULT;

/// WFP operation errors
#[derive(Error, Debug)]
pub enum WfpError {
    /// A WFP API call failed
    ///
    /// `code` is the raw value returned by the API: a Win32 error code or an
    /// `FWP_E_*` HRESULT (`0x8032xxxx`).
    #[error("{op} failed with 0x{code:08X}: {}", system_message(.code))]
    Api {
        /// Name of the failing WFP function (e.g. `FwpmFilterAdd0`)
        op: &'static str,
        /// Raw error code
        code: u32,
    },

    /// Application path not found or could not be converted to NT kernel format
    ///
    /// This error occurs when `FwpmGetAppIdFromFileName0` fails, typically because
    /// the executable does not exist at the specified path.
    #[error("Application path not found or invalid: {0}")]
    AppPathNotFound(String),

    /// The rule uses a condition this crate cannot translate yet
    ///
    /// The rule is rejected rather than installed without the condition,
    /// which would make the filter match all traffic.
    #[error("Unsupported filter condition '{0}': rule rejected to avoid matching all traffic")]
    UnsupportedCondition(String),

    /// The rule is internally inconsistent (e.g. IPv4 and IPv6 conditions mixed)
    #[error("Invalid filter rule: {0}")]
    InvalidRule(String),

    /// Invalid IP address or CIDR prefix
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Insufficient permissions (must run as administrator)
    #[error("Insufficient permissions - administrator privileges required")]
    InsufficientPermissions,

    /// WFP service (BFE) not available
    #[error("Windows Filtering Platform service not available")]
    ServiceNotAvailable,
}

const ERROR_ACCESS_DENIED: u32 = 5;
const E_ACCESSDENIED: u32 = 0x8007_0005;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
const ERROR_SERVICE_DEPENDENCY_DELETED: u32 = 1075;

impl WfpError {
    /// Convert the return value of a WFP API call into a result
    pub(crate) fn check(op: &'static str, code: u32) -> WfpResult<()> {
        match code {
            0 => Ok(()),
            ERROR_ACCESS_DENIED | E_ACCESSDENIED => Err(WfpError::InsufficientPermissions),
            ERROR_SERVICE_NOT_ACTIVE | ERROR_SERVICE_DEPENDENCY_DELETED => {
                Err(WfpError::ServiceNotAvailable)
            }
            _ => Err(WfpError::Api { op, code }),
        }
    }

    /// Raw error code returned by WFP, if this error comes from an API call
    pub fn code(&self) -> Option<u32> {
        match self {
            WfpError::Api { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// Localized system description of a Win32 error code or HRESULT
fn system_message(code: &u32) -> String {
    let hresult = if code & 0x8000_0000 != 0 {
        HRESULT(*code as i32)
    } else {
        HRESULT::from_win32(*code)
    };
    let message = hresult.message();
    let message = message.trim();
    if message.is_empty() {
        "unknown error".to_string()
    } else {
        message.to_string()
    }
}

pub type WfpResult<T> = std::result::Result<T, WfpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        assert_eq!(
            WfpError::InsufficientPermissions.to_string(),
            "Insufficient permissions - administrator privileges required"
        );
        assert_eq!(
            WfpError::ServiceNotAvailable.to_string(),
            "Windows Filtering Platform service not available"
        );
        assert_eq!(
            WfpError::AppPathNotFound(r"C:\missing.exe".into()).to_string(),
            r"Application path not found or invalid: C:\missing.exe"
        );
    }

    #[test]
    fn test_check_success() {
        assert!(WfpError::check("FwpmFilterAdd0", 0).is_ok());
    }

    #[test]
    fn test_check_maps_well_known_codes() {
        for code in [5, 0x8007_0005] {
            assert!(matches!(
                WfpError::check("op", code),
                Err(WfpError::InsufficientPermissions)
            ));
        }
        for code in [1062, 1075] {
            assert!(matches!(
                WfpError::check("op", code),
                Err(WfpError::ServiceNotAvailable)
            ));
        }
    }

    #[test]
    fn test_check_keeps_operation_and_code() {
        let err = WfpError::check("FwpmFilterAdd0", 0x8032_0009).unwrap_err();
        assert!(matches!(
            err,
            WfpError::Api {
                op: "FwpmFilterAdd0",
                code: 0x8032_0009
            }
        ));
        assert_eq!(err.code(), Some(0x8032_0009));
        assert_eq!(WfpError::InsufficientPermissions.code(), None);
    }

    #[test]
    fn test_api_error_display_is_hex_with_message() {
        let err = WfpError::Api {
            op: "FwpmFilterAdd0",
            code: 0x8032_0009,
        };
        let text = err.to_string();
        assert!(
            text.starts_with("FwpmFilterAdd0 failed with 0x80320009: "),
            "{text}"
        );
        assert!(!text.ends_with("unknown error"), "{text}");
    }

    #[test]
    fn test_api_error_display_win32_code() {
        let err = WfpError::Api { op: "op", code: 2 };
        let text = err.to_string();
        assert!(text.starts_with("op failed with 0x00000002: "), "{text}");
        assert!(!text.ends_with("unknown error"), "{text}");
    }
}
