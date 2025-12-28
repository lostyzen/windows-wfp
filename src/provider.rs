//! WFP Provider and Sublayer management
//!
//! Handles registration of TRusTY Wall provider and sublayer in WFP.

use crate::constants::{TRUSTY_PROVIDER_GUID, TRUSTY_SUBLAYER_GUID};
use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use crate::transaction::WfpTransaction;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmProviderAdd0, FwpmSubLayerAdd0, FWPM_PROVIDER0, FWPM_SUBLAYER0,
};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::core::PWSTR;
use std::ptr;

/// WFP Provider for TRusTY Wall
///
/// Registers the application as a WFP provider, allowing it to add filters
/// to the Windows Filtering Platform.
pub struct WfpProvider;

impl WfpProvider {
    /// Register TRusTY Wall as a WFP provider
    ///
    /// This must be called before adding any filters. The provider registration
    /// is persistent and survives reboots.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::Other` if provider registration fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use trusty_wfp::{WfpEngine, WfpProvider};
    ///
    /// let engine = WfpEngine::new()?;
    /// WfpProvider::register(&engine)?;
    /// # Ok::<(), trusty_wfp::WfpError>(())
    /// ```
    pub fn register(engine: &WfpEngine) -> WfpResult<()> {
        // Keep wide strings alive for the duration of the function
        let name_wide: Vec<u16> = "TRusTY Wall".encode_utf16().chain(std::iter::once(0)).collect();
        let desc_wide: Vec<u16> = "TRusTY Wall Firewall Provider".encode_utf16().chain(std::iter::once(0)).collect();

        let provider = FWPM_PROVIDER0 {
            providerKey: TRUSTY_PROVIDER_GUID,
            displayData: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_wide.as_ptr() as *mut u16),
                description: PWSTR(desc_wide.as_ptr() as *mut u16),
            },
            flags: 0,
            providerData: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            serviceName: PWSTR::null(),
        };

        unsafe {
            let result = FwpmProviderAdd0(engine.handle(), &provider, None);

            if result != ERROR_SUCCESS.0 {
                // ERROR_FWP_ALREADY_EXISTS (0x80320009) is acceptable
                if result != 0x80320009 {
                    return Err(WfpError::Other(format!(
                        "Failed to register provider: error code {}",
                        result
                    )));
                }
            }
        }

        Ok(())
    }
}

/// WFP Sublayer for TRusTY Wall filters
///
/// All TRusTY Wall filters are added to this sublayer, allowing them to be
/// managed as a group and ensuring proper priority.
pub struct WfpSublayer;

impl WfpSublayer {
    /// Register TRusTY Wall sublayer
    ///
    /// The sublayer groups all TRusTY Wall filters together and assigns them
    /// a specific weight for priority ordering.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::Other` if sublayer registration fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use trusty_wfp::{WfpEngine, WfpProvider, WfpSublayer};
    ///
    /// let engine = WfpEngine::new()?;
    /// WfpProvider::register(&engine)?;
    /// WfpSublayer::register(&engine)?;
    /// # Ok::<(), trusty_wfp::WfpError>(())
    /// ```
    pub fn register(engine: &WfpEngine) -> WfpResult<()> {
        // Keep wide strings alive for the duration of the function
        let name_wide: Vec<u16> = "TRusTY Wall Filters".encode_utf16().chain(std::iter::once(0)).collect();
        let desc_wide: Vec<u16> = "Sublayer for TRusTY Wall firewall exception filters".encode_utf16().chain(std::iter::once(0)).collect();

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: TRUSTY_SUBLAYER_GUID,
            displayData: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_wide.as_ptr() as *mut u16),
                description: PWSTR(desc_wide.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &TRUSTY_PROVIDER_GUID as *const _ as *mut _,
            providerData: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            weight: 0xFFFF, // Maximum weight - highest priority for TRusTY Wall filters
        };

        unsafe {
            let result = FwpmSubLayerAdd0(engine.handle(), &sublayer, None);

            if result != ERROR_SUCCESS.0 {
                // ERROR_FWP_ALREADY_EXISTS (0x80320009) is acceptable
                if result != 0x80320009 {
                    return Err(WfpError::Other(format!(
                        "Failed to register sublayer: error code {}",
                        result
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Initialize TRusTY Wall WFP provider and sublayer
///
/// Convenience function that registers both the provider and sublayer
/// in a single transaction.
///
/// # Errors
///
/// Returns `WfpError` if registration fails.
///
/// # Examples
///
/// ```no_run
/// use trusty_wfp::{WfpEngine, initialize_wfp};
///
/// let engine = WfpEngine::new()?;
/// initialize_wfp(&engine)?;
/// // Now ready to add filters
/// # Ok::<(), trusty_wfp::WfpError>(())
/// ```
pub fn initialize_wfp(engine: &WfpEngine) -> WfpResult<()> {
    let txn = WfpTransaction::begin(engine)?;

    WfpProvider::register(engine)?;
    WfpSublayer::register(engine)?;

    txn.commit()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires admin privileges
    fn test_provider_registration() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        let result = WfpProvider::register(&engine);

        // Should succeed or already exist
        assert!(result.is_ok(), "Failed to register provider: {:?}", result);
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_sublayer_registration() {
        let engine = WfpEngine::new().expect("Failed to create engine");

        // Provider must be registered first
        WfpProvider::register(&engine).expect("Failed to register provider");

        let result = WfpSublayer::register(&engine);
        assert!(result.is_ok(), "Failed to register sublayer: {:?}", result);
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_initialize_wfp() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        let result = initialize_wfp(&engine);

        assert!(result.is_ok(), "Failed to initialize WFP: {:?}", result);
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_double_registration_is_idempotent() {
        let engine = WfpEngine::new().expect("Failed to create engine");

        // First registration
        initialize_wfp(&engine).expect("First registration failed");

        // Second registration should also succeed (idempotent)
        let result = initialize_wfp(&engine);
        assert!(result.is_ok(), "Double registration should be idempotent");
    }
}
