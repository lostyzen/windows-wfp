//! WFP Filter translation from FilterRule
//!
//! Translates FilterRule into WFP FWPM_FILTER0 structures.
//!
//! # Path Format Conversion
//!
//! **CRITICAL**: WFP operates at the Windows kernel level and requires NT kernel paths,
//! not DOS paths. This module automatically converts DOS paths to NT kernel format using
//! the `FwpmGetAppIdFromFileName0` API.
//!
//! ## Why This Matters
//!
//! - **DOS path**: `C:\Windows\System32\curl.exe` (user-friendly format)
//! - **NT kernel path**: `\device\harddiskvolume4\windows\system32\curl.exe` (kernel format)
//!
//! When a process makes a network connection, WFP identifies it using the NT kernel path.
//! If your filter uses a DOS path, it will be added successfully but will **never match**
//! any traffic because the path comparison fails at the kernel level.
//!
//! ## Implementation
//!
//! The `add_filter()` method automatically handles this conversion:
//! 1. Takes a DOS path from `FilterRule.app_path` (e.g., `PathBuf::from(r"C:\Windows\System32\curl.exe")`)
//! 2. Calls `FwpmGetAppIdFromFileName0` to convert it to NT kernel format
//! 3. Uses the converted path in the WFP filter condition
//! 4. Properly frees the allocated memory after filter creation
//!
//! This ensures filters work correctly without requiring users to know about NT kernel paths.

use crate::condition::Protocol;
use crate::constants::*;
use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use crate::filter::{Action, FilterRule};
use crate::layer;
use std::net::IpAddr;
use std::ptr;
use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAGS, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL,
    FWP_UINT16, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
};

/// WFP Filter builder
///
/// Translates [`FilterRule`] into WFP filter structures and manages filter lifecycle.
///
/// # Examples
///
/// ```no_run
/// use windows_wfp::{WfpEngine, FilterBuilder, FilterRule, Direction, Action, FilterWeight, initialize_wfp};
///
/// let engine = WfpEngine::new()?;
/// initialize_wfp(&engine)?;
///
/// let rule = FilterRule::new("Block curl", Direction::Outbound, Action::Block)
///     .with_weight(FilterWeight::UserBlock)
///     .with_app_path(r"C:\Windows\System32\curl.exe");
///
/// let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
/// // Later: remove the filter
/// FilterBuilder::delete_filter(&engine, filter_id)?;
/// # Ok::<(), windows_wfp::WfpError>(())
/// ```
pub struct FilterBuilder;

impl FilterBuilder {
    /// Translate Action to WFP action type
    fn translate_action(action: Action) -> FWP_ACTION_TYPE {
        match action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        }
    }

    /// Translate Protocol to IP protocol number
    fn translate_protocol(protocol: Protocol) -> u8 {
        protocol.as_u8()
    }

    /// Convert CIDR prefix length to IPv4 netmask
    ///
    /// Example: prefix_len=24 → 0xFFFFFF00 (255.255.255.0)
    fn prefix_to_v4_mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            u32::MAX << (32 - prefix_len)
        }
    }

    /// Add filter to WFP engine
    ///
    /// Translates a [`FilterRule`] and adds it to the WFP engine.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::FilterAddFailed` if the filter cannot be added.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_wfp::{WfpEngine, FilterBuilder, FilterRule, Direction, Action, FilterWeight, initialize_wfp};
    ///
    /// let engine = WfpEngine::new()?;
    /// initialize_wfp(&engine)?;
    ///
    /// let rule = FilterRule::new("Allow all outbound", Direction::Outbound, Action::Permit)
    ///     .with_weight(FilterWeight::DefaultPermit);
    /// let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
    /// # Ok::<(), windows_wfp::WfpError>(())
    /// ```
    pub fn add_filter(engine: &WfpEngine, rule: &FilterRule) -> WfpResult<u64> {
        // Determine if rule uses IPv6 (check both remote_ip and local_ip)
        let is_ipv6 = rule
            .remote_ip
            .as_ref()
            .map(|ip| ip.is_ipv6())
            .or_else(|| rule.local_ip.as_ref().map(|ip| ip.is_ipv6()))
            .unwrap_or(false);

        let layer_key = layer::select_layer(rule.direction, is_ipv6);
        let action = Self::translate_action(rule.action);

        // Convert name to wide string - must outlive FwpmFilterAdd0 call
        let name_wide: Vec<u16> = rule.name.encode_utf16().chain(std::iter::once(0)).collect();

        // Weight storage - must outlive FwpmFilterAdd0 call
        let weight_value: u64 = rule.weight;

        // CRITICAL: Convert DOS path to NT kernel format using FwpmGetAppIdFromFileName0.
        // If the conversion fails (e.g. file not found), return an error instead of silently
        // skipping the condition, which would cause the filter to match ALL applications.
        let app_id_blob: Option<*mut FWP_BYTE_BLOB> = if let Some(app_path) = &rule.app_path {
            let path_str = app_path.to_string_lossy().to_string();
            // path_wide must remain alive for the duration of the API call
            let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

            let mut blob_ptr: *mut FWP_BYTE_BLOB = ptr::null_mut();
            let result = unsafe {
                FwpmGetAppIdFromFileName0(PWSTR(path_wide.as_ptr() as *mut u16), &mut blob_ptr)
            };

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::AppPathNotFound(path_str));
            }

            Some(blob_ptr)
        } else {
            None
        };

        let remote_v4_mask: Option<FWP_V4_ADDR_AND_MASK> =
            rule.remote_ip.as_ref().and_then(|remote_ip| {
                if let IpAddr::V4(ipv4) = remote_ip.addr {
                    Some(FWP_V4_ADDR_AND_MASK {
                        addr: u32::from_be_bytes(ipv4.octets()),
                        mask: Self::prefix_to_v4_mask(remote_ip.prefix_len),
                    })
                } else {
                    None
                }
            });

        let remote_v6_mask: Option<FWP_V6_ADDR_AND_MASK> =
            rule.remote_ip.as_ref().and_then(|remote_ip| {
                if let IpAddr::V6(ipv6) = remote_ip.addr {
                    Some(FWP_V6_ADDR_AND_MASK {
                        addr: ipv6.octets(),
                        prefixLength: remote_ip.prefix_len,
                    })
                } else {
                    None
                }
            });

        let local_v4_mask: Option<FWP_V4_ADDR_AND_MASK> =
            rule.local_ip.as_ref().and_then(|local_ip| {
                if let IpAddr::V4(ipv4) = local_ip.addr {
                    Some(FWP_V4_ADDR_AND_MASK {
                        addr: u32::from_be_bytes(ipv4.octets()),
                        mask: Self::prefix_to_v4_mask(local_ip.prefix_len),
                    })
                } else {
                    None
                }
            });

        let local_v6_mask: Option<FWP_V6_ADDR_AND_MASK> =
            rule.local_ip.as_ref().and_then(|local_ip| {
                if let IpAddr::V6(ipv6) = local_ip.addr {
                    Some(FWP_V6_ADDR_AND_MASK {
                        addr: ipv6.octets(),
                        prefixLength: local_ip.prefix_len,
                    })
                } else {
                    None
                }
            });

        // Build conditions
        let mut conditions = Vec::new();

        // Condition: APP_ID (application path in NT kernel format)
        if let Some(blob_ptr) = app_id_blob {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        byteBlob: blob_ptr,
                    },
                },
            });
        }

        // Condition: REMOTE_PORT
        if let Some(remote_port) = rule.remote_port {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        uint16: remote_port,
                    },
                },
            });
        }

        // Condition: LOCAL_PORT
        if let Some(local_port) = rule.local_port {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_IP_LOCAL_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        uint16: local_port,
                    },
                },
            });
        }

        // Condition: PROTOCOL
        if let Some(protocol) = rule.protocol {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        uint8: Self::translate_protocol(protocol),
                    },
                },
            });
        }

        // Condition: REMOTE_IP (IPv4)
        if let Some(ref mask) = remote_v4_mask {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: mask as *const _ as *mut _,
                    },
                },
            });
        }

        // Condition: REMOTE_IP (IPv6)
        if let Some(ref mask) = remote_v6_mask {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: mask as *const _ as *mut _,
                    },
                },
            });
        }

        // Condition: LOCAL_IP (IPv4)
        if let Some(ref mask) = local_v4_mask {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_IP_LOCAL_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: mask as *const _ as *mut _,
                    },
                },
            });
        }

        // Condition: LOCAL_IP (IPv6)
        if let Some(ref mask) = local_v6_mask {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_IP_LOCAL_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: mask as *const _ as *mut _,
                    },
                },
            });
        }

        // Create the filter structure
        let filter = FWPM_FILTER0 {
            filterKey: GUID::zeroed(),
            displayData:
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name_wide.as_ptr() as *mut u16),
                    description: PWSTR::null(),
                },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &WFP_PROVIDER_GUID as *const _ as *mut _,
            providerData:
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                    size: 0,
                    data: ptr::null_mut(),
                },
            layerKey: layer_key,
            subLayerKey: WFP_SUBLAYER_GUID,
            weight: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous:
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                        uint64: &weight_value as *const u64 as *mut u64,
                    },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                ptr::null_mut()
            } else {
                conditions.as_ptr() as *mut _
            },
            action: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0 {
                r#type: action,
                Anonymous: Default::default(),
            },
            Anonymous: Default::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: Default::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(engine.handle(), &filter, None, Some(&mut filter_id));

            // Free memory allocated by FwpmGetAppIdFromFileName0 regardless of add result
            if let Some(mut blob_ptr) = app_id_blob {
                if !blob_ptr.is_null() {
                    FwpmFreeMemory0(&mut blob_ptr as *mut _ as *mut *mut _);
                }
            }

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::FilterAddFailed(format!(
                    "Failed to add filter '{}': error code {}",
                    rule.name, result
                )));
            }
        }

        Ok(filter_id)
    }

    /// Delete filter from WFP engine by ID
    ///
    /// Removes a previously added filter using its unique ID.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::FilterDeleteFailed` if the filter cannot be deleted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_wfp::{WfpEngine, FilterBuilder, FilterRule, Direction, Action, FilterWeight, initialize_wfp};
    ///
    /// let engine = WfpEngine::new()?;
    /// initialize_wfp(&engine)?;
    ///
    /// let rule = FilterRule::new("Allow all", Direction::Outbound, Action::Permit)
    ///     .with_weight(FilterWeight::DefaultPermit);
    /// let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
    ///
    /// // Later: remove the filter
    /// FilterBuilder::delete_filter(&engine, filter_id)?;
    /// # Ok::<(), windows_wfp::WfpError>(())
    /// ```
    pub fn delete_filter(engine: &WfpEngine, filter_id: u64) -> WfpResult<()> {
        unsafe {
            let result = FwpmFilterDeleteById0(engine.handle(), filter_id);

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::FilterDeleteFailed(format!(
                    "Failed to delete filter ID {}: error code {}",
                    filter_id, result
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::Protocol;
    use crate::filter::{Action, FilterRule};

    #[test]
    fn test_action_translation() {
        assert_eq!(
            FilterBuilder::translate_action(Action::Permit),
            FWP_ACTION_PERMIT
        );
        assert_eq!(
            FilterBuilder::translate_action(Action::Block),
            FWP_ACTION_BLOCK
        );
    }

    #[test]
    fn test_protocol_translation() {
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Hopopt), 0);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Icmp), 1);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Igmp), 2);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Tcp), 6);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Udp), 17);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Gre), 47);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Esp), 50);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Ah), 51);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Icmpv6), 58);
    }

    #[test]
    fn test_prefix_to_v4_mask() {
        assert_eq!(FilterBuilder::prefix_to_v4_mask(0), 0x00000000);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(8), 0xFF000000);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(16), 0xFFFF0000);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(24), 0xFFFFFF00);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(32), 0xFFFFFFFF);
    }

    #[test]
    fn test_prefix_to_v4_mask_all_values() {
        assert_eq!(FilterBuilder::prefix_to_v4_mask(1), 0x80000000);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(4), 0xF0000000);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(12), 0xFFF00000);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(20), 0xFFFFF000);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(28), 0xFFFFFFF0);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(31), 0xFFFFFFFE);
    }

    #[test]
    fn test_prefix_to_v4_mask_overflow() {
        // prefix > 32 should saturate to all ones
        assert_eq!(FilterBuilder::prefix_to_v4_mask(33), 0xFFFFFFFF);
        assert_eq!(FilterBuilder::prefix_to_v4_mask(255), 0xFFFFFFFF);
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_add_simple_filter() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        crate::initialize_wfp(&engine).expect("Failed to initialize WFP");

        let rule = FilterRule::allow_all_outbound();
        let result = FilterBuilder::add_filter(&engine, &rule);

        assert!(result.is_ok(), "Failed to add filter: {:?}", result);
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_add_and_delete_filter() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        crate::initialize_wfp(&engine).expect("Failed to initialize WFP");

        let rule = FilterRule::allow_all_outbound();

        let filter_id = FilterBuilder::add_filter(&engine, &rule).expect("Failed to add filter");
        let result = FilterBuilder::delete_filter(&engine, filter_id);

        assert!(result.is_ok(), "Failed to delete filter: {:?}", result);
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_add_filter_with_nonexistent_app_path_returns_error() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        crate::initialize_wfp(&engine).expect("Failed to initialize WFP");

        let rule = FilterRule::new("Test", crate::Direction::Outbound, crate::Action::Block)
            .with_app_path(r"C:\this\path\does\not\exist.exe");

        let result = FilterBuilder::add_filter(&engine, &rule);
        assert!(
            matches!(result, Err(WfpError::AppPathNotFound(_))),
            "Expected AppPathNotFound, got: {:?}",
            result
        );
    }
}
