//! WFP Engine wrapper with RAII handle management
//!
//! Provides safe Rust wrapper around WFP engine session.

use crate::errors::{WfpError, WfpResult};
use std::ptr;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
};

/// WFP Engine session with RAII handle management
///
/// Opens a session to the Windows Filtering Platform on creation
/// and automatically closes it on drop.
///
/// # Examples
///
/// ```no_run
/// use windows_wfp::WfpEngine;
///
/// let engine = WfpEngine::new()?;
/// // Use engine for filter operations
/// // Session automatically closed when engine goes out of scope
/// # Ok::<(), windows_wfp::WfpError>(())
/// ```
#[derive(Debug)]
pub struct WfpEngine {
    /// Handle to WFP engine session
    handle: HANDLE,
}

impl WfpEngine {
    /// Open a new WFP engine session
    ///
    /// Requires administrator privileges.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::EngineOpenFailed` if:
    /// - Insufficient permissions (not running as admin)
    /// - WFP service not available
    /// - Session creation failed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_wfp::WfpEngine;
    ///
    /// let engine = WfpEngine::new()?;
    /// # Ok::<(), windows_wfp::WfpError>(())
    /// ```
    pub fn new() -> WfpResult<Self> {
        Self::new_with_flags(FWPM_SESSION_FLAG_DYNAMIC)
    }

    /// Open a new WFP engine session with custom flags
    ///
    /// # Arguments
    ///
    /// * `flags` - Session flags (e.g., `FWPM_SESSION_FLAG_DYNAMIC` for automatic cleanup)
    ///
    /// # Errors
    ///
    /// Returns `WfpError::EngineOpenFailed` if session creation fails.
    pub fn new_with_flags(flags: u32) -> WfpResult<Self> {
        let session = FWPM_SESSION0 {
            sessionKey: windows::core::GUID::zeroed(),
            displayData: Default::default(),
            flags,
            txnWaitTimeoutInMSec: 0,
            processId: 0,
            sid: ptr::null_mut(),
            username: PWSTR::null(),
            kernelMode: false.into(),
        };

        let mut handle = HANDLE::default();

        unsafe {
            let result = FwpmEngineOpen0(
                PCWSTR::null(),
                10, // RPC_C_AUTHN_WINNT (Windows NT authentication)
                None,
                Some(&session),
                &mut handle,
            );

            if result != ERROR_SUCCESS.0 {
                return match result {
                    5 => Err(WfpError::InsufficientPermissions),
                    1062 | 1075 => Err(WfpError::ServiceNotAvailable),
                    _ => Err(WfpError::Other(format!(
                        "FwpmEngineOpen0 failed with Windows error code: {} (0x{:X}). \
                        Common causes: BFE service not running, insufficient privileges, or WFP driver not loaded.",
                        result, result
                    ))),
                };
            }
        }

        Ok(Self { handle })
    }

    /// Get raw handle to WFP engine session
    ///
    /// # Safety
    ///
    /// The handle is only valid while this `WfpEngine` instance is alive.
    /// Do not close the handle manually - it will be closed automatically on drop.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Check if session is valid
    pub fn is_valid(&self) -> bool {
        !self.handle.is_invalid()
    }
}

impl Drop for WfpEngine {
    /// Automatically close WFP engine session when dropped
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }
}

// WfpEngine is Send because the handle can be safely transferred between threads
unsafe impl Send for WfpEngine {}

// WfpEngine is NOT Sync because concurrent access requires synchronization
// Multiple threads should not access the same session simultaneously

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires admin privileges
    fn test_engine_creation() {
        let engine = WfpEngine::new();
        assert!(engine.is_ok(), "Failed to create WFP engine (run as admin)");

        if let Ok(engine) = engine {
            assert!(engine.is_valid());
            assert!(!engine.handle().is_invalid());
        }
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_engine_drop_closes_session() {
        {
            let _engine = WfpEngine::new().expect("Failed to create engine");
            // Engine should be valid here
        }
        // Engine dropped - session should be closed automatically
        // No way to verify programmatically without leaking handles
    }

    #[test]
    fn test_engine_without_permissions() {
        // This test will fail if run as admin
        // Useful for CI/CD without admin rights
        let result = WfpEngine::new();

        if let Err(err) = result {
            // Expected when not running as admin
            match err {
                WfpError::InsufficientPermissions => (),
                WfpError::ServiceNotAvailable => (),
                WfpError::EngineOpenFailed => (),
                other => panic!("Unexpected error: {:?}", other),
            }
        }
    }
}
