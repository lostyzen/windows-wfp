//! WFP Filter Enumeration
//!
//! Enumerate active WFP filters in the system. Useful for debugging,
//! auditing, and discovering filters from other firewall software.
//!
//! # Example
//!
//! ```no_run
//! use windows_wfp::{WfpEngine, FilterEnumerator, FilterInfo};
//!
//! let engine = WfpEngine::new()?;
//! let filters: Vec<FilterInfo> = FilterEnumerator::all(&engine)?;
//!
//! for filter in &filters {
//!     println!("{}: {} ({:?})", filter.id, filter.name, filter.action);
//! }
//! # Ok::<(), windows_wfp::WfpError>(())
//! ```

use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use std::path::PathBuf;
use std::ptr;
use windows::core::GUID;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FWPM_FILTER0, FWP_ACTION_BLOCK, FWP_ACTION_CALLOUT_INSPECTION, FWP_ACTION_CALLOUT_TERMINATING,
    FWP_ACTION_CALLOUT_UNKNOWN, FWP_ACTION_PERMIT, FWP_BYTE_BLOB_TYPE, FWP_EMPTY, FWP_UINT16,
    FWP_UINT32, FWP_UINT64, FWP_UINT8,
};

use crate::constants::CONDITION_ALE_APP_ID;

/// Action type of a WFP filter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// Block traffic
    Block,
    /// Permit traffic
    Permit,
    /// Callout (terminating)
    CalloutTerminating,
    /// Callout (inspection only)
    CalloutInspection,
    /// Callout (unknown)
    CalloutUnknown,
    /// Other action type
    Other(u32),
}

/// Information about an active WFP filter
#[derive(Debug, Clone)]
pub struct FilterInfo {
    /// WFP filter ID
    pub id: u64,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Filter action (Block, Permit, Callout)
    pub action: FilterAction,
    /// Provider GUID (if set)
    pub provider_key: Option<GUID>,
    /// Filter weight/priority
    pub weight: u64,
    /// Layer GUID where the filter is installed
    pub layer_key: GUID,
    /// Sublayer GUID
    pub sublayer_key: GUID,
    /// Application path extracted from conditions (if present)
    pub app_path: Option<PathBuf>,
    /// Number of conditions on this filter
    pub num_conditions: u32,
}

/// Enumerates WFP filters from the system
///
/// Provides methods to list all active filters; callers can then filter by provider if desired.
///
/// # Example
///
/// ```no_run
/// use windows_wfp::{WfpEngine, FilterEnumerator};
///
/// let engine = WfpEngine::new()?;
///
/// // List all filters
/// let all = FilterEnumerator::all(&engine)?;
/// println!("Total filters: {}", all.len());
///
/// // Filter by provider GUID
/// use windows::core::GUID;
/// let my_guid = GUID::from_u128(0x12345678_1234_5678_1234_567812345678);
/// let mine: Vec<_> = all.iter().filter(|f| f.provider_key == Some(my_guid)).collect();
/// # Ok::<(), windows_wfp::WfpError>(())
/// ```
pub struct FilterEnumerator;

impl FilterEnumerator {
    /// Enumerate all active WFP filters
    ///
    /// Returns a vector of [`FilterInfo`] for every filter currently registered in WFP.
    ///
    /// # Errors
    ///
    /// Returns an error if the enumeration handle cannot be created or enumeration fails.
    /// Requires administrator privileges.
    pub fn all(engine: &WfpEngine) -> WfpResult<Vec<FilterInfo>> {
        let mut enum_handle = HANDLE::default();

        unsafe {
            let result = FwpmFilterCreateEnumHandle0(engine.handle(), None, &mut enum_handle);

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::Other(format!(
                    "Failed to create filter enum handle: error code {}",
                    result
                )));
            }
        }

        let mut filters = Vec::new();
        let batch_size = 100;

        loop {
            let mut filter_array: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut num_returned: u32 = 0;

            unsafe {
                let result = FwpmFilterEnum0(
                    engine.handle(),
                    enum_handle,
                    batch_size,
                    &mut filter_array,
                    &mut num_returned,
                );

                if result != ERROR_SUCCESS.0 {
                    let _ = FwpmFilterDestroyEnumHandle0(engine.handle(), enum_handle);
                    return Err(WfpError::Other(format!(
                        "Failed to enumerate filters: error code {}",
                        result
                    )));
                }

                if num_returned == 0 {
                    if !filter_array.is_null() {
                        FwpmFreeMemory0(&mut filter_array as *mut _ as *mut *mut _);
                    }
                    break;
                }

                for i in 0..num_returned {
                    let filter = &**filter_array.offset(i as isize);
                    filters.push(parse_filter(filter));
                }

                if !filter_array.is_null() {
                    FwpmFreeMemory0(&mut filter_array as *mut _ as *mut *mut _);
                }
            }
        }

        unsafe {
            let _ = FwpmFilterDestroyEnumHandle0(engine.handle(), enum_handle);
        }

        Ok(filters)
    }

    /// Count all active WFP filters without collecting details
    ///
    /// Only counts filters without parsing their contents, avoiding
    /// string allocations and condition extraction.
    pub fn count(engine: &WfpEngine) -> WfpResult<usize> {
        let mut enum_handle = HANDLE::default();

        unsafe {
            let result = FwpmFilterCreateEnumHandle0(engine.handle(), None, &mut enum_handle);

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::Other(format!(
                    "Failed to create filter enum handle: error code {}",
                    result
                )));
            }
        }

        let mut count: usize = 0;
        let batch_size = 100;

        loop {
            let mut filter_array: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut num_returned: u32 = 0;

            unsafe {
                let result = FwpmFilterEnum0(
                    engine.handle(),
                    enum_handle,
                    batch_size,
                    &mut filter_array,
                    &mut num_returned,
                );

                if result != ERROR_SUCCESS.0 {
                    let _ = FwpmFilterDestroyEnumHandle0(engine.handle(), enum_handle);
                    return Err(WfpError::Other(format!(
                        "Failed to enumerate filters: error code {}",
                        result
                    )));
                }

                if num_returned == 0 {
                    if !filter_array.is_null() {
                        FwpmFreeMemory0(&mut filter_array as *mut _ as *mut *mut _);
                    }
                    break;
                }

                count += num_returned as usize;

                if !filter_array.is_null() {
                    FwpmFreeMemory0(&mut filter_array as *mut _ as *mut *mut _);
                }
            }
        }

        unsafe {
            let _ = FwpmFilterDestroyEnumHandle0(engine.handle(), enum_handle);
        }

        Ok(count)
    }
}

/// Parse a raw FWPM_FILTER0 into FilterInfo
///
/// # Safety
///
/// The filter pointer must be valid.
unsafe fn parse_filter(filter: &FWPM_FILTER0) -> FilterInfo {
    let name = if !filter.displayData.name.is_null() {
        filter
            .displayData
            .name
            .to_string()
            .unwrap_or_else(|_| String::new())
    } else {
        String::new()
    };

    let description = if !filter.displayData.description.is_null() {
        filter
            .displayData
            .description
            .to_string()
            .unwrap_or_else(|_| String::new())
    } else {
        String::new()
    };

    let action = match filter.action.r#type {
        FWP_ACTION_BLOCK => FilterAction::Block,
        FWP_ACTION_PERMIT => FilterAction::Permit,
        FWP_ACTION_CALLOUT_TERMINATING => FilterAction::CalloutTerminating,
        FWP_ACTION_CALLOUT_INSPECTION => FilterAction::CalloutInspection,
        FWP_ACTION_CALLOUT_UNKNOWN => FilterAction::CalloutUnknown,
        other => FilterAction::Other(other.0),
    };

    let provider_key = if !filter.providerKey.is_null() {
        Some(*filter.providerKey)
    } else {
        None
    };

    let weight = match filter.weight.r#type {
        FWP_UINT8 => filter.weight.Anonymous.uint8 as u64,
        FWP_UINT16 => filter.weight.Anonymous.uint16 as u64,
        FWP_UINT32 => filter.weight.Anonymous.uint32 as u64,
        FWP_UINT64 => {
            let ptr = filter.weight.Anonymous.uint64;
            if ptr.is_null() {
                0
            } else {
                *ptr
            }
        }
        FWP_EMPTY => 0,
        _ => 0,
    };

    let app_path = extract_app_path(filter);

    FilterInfo {
        id: filter.filterId,
        name,
        description,
        action,
        provider_key,
        weight,
        layer_key: filter.layerKey,
        sublayer_key: filter.subLayerKey,
        app_path,
        num_conditions: filter.numFilterConditions,
    }
}

/// Extract application path from filter conditions
///
/// Looks for FWPM_CONDITION_ALE_APP_ID in the filter's conditions
/// and decodes the wide-string blob.
unsafe fn extract_app_path(filter: &FWPM_FILTER0) -> Option<PathBuf> {
    if filter.numFilterConditions == 0 || filter.filterCondition.is_null() {
        return None;
    }

    let conditions =
        std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize);

    let condition = conditions
        .iter()
        .find(|c| c.fieldKey == CONDITION_ALE_APP_ID)?;

    if condition.conditionValue.r#type != FWP_BYTE_BLOB_TYPE {
        return None;
    }

    let blob_ptr = condition.conditionValue.Anonymous.byteBlob;
    if blob_ptr.is_null() {
        return None;
    }

    let blob = &*blob_ptr;
    if blob.data.is_null() || blob.size == 0 || (blob.size % 2) != 0 {
        return None;
    }

    let wide_slice = std::slice::from_raw_parts(blob.data as *const u16, (blob.size / 2) as usize);
    let null_pos = wide_slice
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(wide_slice.len());

    String::from_utf16(&wide_slice[..null_pos])
        .ok()
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_action_eq() {
        assert_eq!(FilterAction::Block, FilterAction::Block);
        assert_eq!(FilterAction::Permit, FilterAction::Permit);
        assert_ne!(FilterAction::Block, FilterAction::Permit);
        assert_eq!(FilterAction::Other(42), FilterAction::Other(42));
        assert_ne!(FilterAction::Other(1), FilterAction::Other(2));
    }

    #[test]
    fn test_filter_action_copy() {
        let action = FilterAction::Block;
        let copy = action;
        assert_eq!(action, copy);
    }

    #[test]
    fn test_filter_info_clone() {
        let info = FilterInfo {
            id: 42,
            name: "Test filter".to_string(),
            description: "A test".to_string(),
            action: FilterAction::Block,
            provider_key: None,
            weight: 1000,
            layer_key: GUID::zeroed(),
            sublayer_key: GUID::zeroed(),
            app_path: Some(PathBuf::from(r"C:\test.exe")),
            num_conditions: 1,
        };

        let cloned = info.clone();
        assert_eq!(cloned.id, 42);
        assert_eq!(cloned.name, "Test filter");
        assert_eq!(cloned.action, FilterAction::Block);
        assert!(cloned.app_path.is_some());
    }

    #[test]
    fn test_filter_info_default_values() {
        let info = FilterInfo {
            id: 0,
            name: String::new(),
            description: String::new(),
            action: FilterAction::Permit,
            provider_key: None,
            weight: 0,
            layer_key: GUID::zeroed(),
            sublayer_key: GUID::zeroed(),
            app_path: None,
            num_conditions: 0,
        };

        assert_eq!(info.id, 0);
        assert!(info.name.is_empty());
        assert!(info.provider_key.is_none());
        assert!(info.app_path.is_none());
    }

    #[test]
    fn test_filter_info_with_provider() {
        let guid = GUID::from_u128(0x12345678_1234_5678_1234_567812345678);
        let info = FilterInfo {
            id: 100,
            name: "Provider filter".to_string(),
            description: String::new(),
            action: FilterAction::Block,
            provider_key: Some(guid),
            weight: 5000,
            layer_key: GUID::zeroed(),
            sublayer_key: GUID::zeroed(),
            app_path: None,
            num_conditions: 3,
        };

        assert_eq!(info.provider_key, Some(guid));
        assert_eq!(info.num_conditions, 3);
    }

    #[test]
    #[ignore] // Requires administrator privileges
    fn test_enumerate_all_filters() {
        let engine = WfpEngine::new().expect("Failed to open WFP engine");
        let filters = FilterEnumerator::all(&engine).expect("Failed to enumerate");
        // Any Windows system should have at least some WFP filters
        assert!(!filters.is_empty(), "Expected at least one WFP filter");
    }

    #[test]
    #[ignore] // Requires administrator privileges
    fn test_count_filters() {
        let engine = WfpEngine::new().expect("Failed to open WFP engine");
        let count = FilterEnumerator::count(&engine).expect("Failed to count");
        let all = FilterEnumerator::all(&engine).expect("Failed to enumerate");
        assert_eq!(count, all.len());
    }
}
