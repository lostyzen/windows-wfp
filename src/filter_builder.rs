//! WFP Filter translation from domain RuleDef
//!
//! Translates platform-agnostic RuleDef into WFP FWPM_FILTER0 structures.
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
//! 1. Takes a DOS path from `RuleDef.app_path` (e.g., `PathBuf::from(r"C:\Windows\System32\curl.exe")`)
//! 2. Calls `FwpmGetAppIdFromFileName0` to convert it to NT kernel format
//! 3. Uses the converted path in the WFP filter condition
//! 4. Properly frees the allocated memory after filter creation
//!
//! This ensures filters work correctly without requiring users to know about NT kernel paths.

use crate::constants::*;
use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
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

// Import domain types
use trusty_domain::{Direction, Protocol, RuleAction, RuleDef};

/// WFP Filter builder
///
/// Translates domain RuleDef into WFP filter structures.
pub struct FilterBuilder;

impl FilterBuilder {
    /// Translate RuleDef to WFP layer GUID
    ///
    /// Maps direction to appropriate WFP layer based on IPv4/IPv6.
    fn select_layer(direction: Direction, is_ipv6: bool) -> GUID {
        match (direction, is_ipv6) {
            (Direction::Outbound, false) => LAYER_ALE_AUTH_CONNECT_V4,
            (Direction::Outbound, true) => LAYER_ALE_AUTH_CONNECT_V6,
            (Direction::Inbound, false) => LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            (Direction::Inbound, true) => LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        }
    }

    /// Translate RuleAction to WFP action
    fn translate_action(action: RuleAction) -> FWP_ACTION_TYPE {
        match action {
            RuleAction::Allow => FWP_ACTION_PERMIT,
            RuleAction::Block => FWP_ACTION_BLOCK,
        }
    }

    /// Translate Protocol to IP protocol number
    fn translate_protocol(protocol: Protocol) -> u8 {
        protocol as u8 // Already has correct values: Tcp=6, Udp=17, Icmp=1, Icmpv6=58
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
    /// Translates RuleDef and adds it to WFP within a transaction.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::FilterAddFailed` if the filter cannot be added.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use trusty_wfp::{WfpEngine, FilterBuilder, initialize_wfp};
    /// use trusty_domain::RuleDef;
    ///
    /// let engine = WfpEngine::new()?;
    /// initialize_wfp(&engine)?;
    ///
    /// let rule = RuleDef::allow_outbound();
    /// let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
    /// # Ok::<(), trusty_wfp::WfpError>(())
    /// ```
    pub fn add_filter(engine: &WfpEngine, rule: &RuleDef) -> WfpResult<u64> {
        // Determine if rule uses IPv6 (based on remote_ip if present)
        let is_ipv6 = rule
            .remote_ip
            .as_ref()
            .map(|ip_mask| matches!(ip_mask.addr, IpAddr::V6(_)))
            .unwrap_or(false);

        let layer_key = Self::select_layer(rule.direction, is_ipv6);
        let action = Self::translate_action(rule.action);

        // Convert name to wide string - must outlive FwpmFilterAdd0 call
        let name_wide: Vec<u16> = rule.name.encode_utf16().chain(std::iter::once(0)).collect();

        // Weight storage - must outlive FwpmFilterAdd0 call
        //
        // IMPORTANT: WFP supports different weight types (FWP_UINT8, FWP_UINT64, etc.)
        // TinyWall uses FWP_UINT64 to store FilterWeight values directly in millions (3M-9M).
        // This gives much finer-grained priority control than the 0-15 range of FWP_UINT8.
        //
        // Priority formula: Sublayer Weight (0xFFFF) + Filter Weight (millions)
        // Example: Sublayer 65535 + UserBlock 6000000 = Total priority 6065535
        let weight_value: u64 = rule.weight;

        // Storage for condition data that must outlive FwpmFilterAdd0 call

        // CRITICAL: Convert DOS path to NT kernel format using FwpmGetAppIdFromFileName0
        //
        // WFP operates at the kernel level and requires NT kernel paths, not DOS paths:
        // - DOS path:    C:\Windows\System32\curl.exe
        // - NT path:     \device\harddiskvolume4\windows\system32\curl.exe
        //
        // Without this conversion, filters will be added successfully but will NEVER match
        // any actual network traffic because WFP compares the filter path against the
        // kernel-level path of the process making the connection.
        //
        // FwpmGetAppIdFromFileName0 performs the conversion and returns a FWP_BYTE_BLOB
        // containing the NT kernel path as a wide string. This blob must be freed with
        // FwpmFreeMemory0 after the filter is added.
        let app_id_blob: Option<(*mut FWP_BYTE_BLOB, bool)> =
            rule.app_path.as_ref().and_then(|app_path| {
                unsafe {
                    let path_str = app_path.to_string_lossy().to_string();
                    let path_wide: Vec<u16> =
                        path_str.encode_utf16().chain(std::iter::once(0)).collect();
                    let pwstr = PWSTR(path_wide.as_ptr() as *mut u16);

                    let mut blob_ptr: *mut FWP_BYTE_BLOB = ptr::null_mut();
                    let result = FwpmGetAppIdFromFileName0(pwstr, &mut blob_ptr);

                    if result == ERROR_SUCCESS.0 {
                        // Successfully converted DOS path to NT kernel format
                        // The blob_ptr now points to WFP-allocated memory containing the NT path
                        Some((blob_ptr, true)) // true = needs FwpmFreeMemory0 cleanup
                    } else {
                        // Conversion failed - file may not exist or path is invalid
                        // Return None to skip APP_ID condition entirely
                        None
                    }
                }
            });

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

        // Build conditions - now all data is stored above and will outlive this call
        let mut conditions = Vec::new();

        // Condition: APP_ID (application path in NT kernel format)
        if let Some((blob_ptr, _)) = app_id_blob {
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
                        uint16: remote_port.value(),
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
                        uint16: local_port.value(),
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
            filterKey: GUID::zeroed(), // Let WFP generate GUID
            displayData:
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name_wide.as_ptr() as *mut u16),
                    description: PWSTR::null(),
                },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &TRUSTY_PROVIDER_GUID as *const _ as *mut _,
            providerData:
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                    size: 0,
                    data: ptr::null_mut(),
                },
            layerKey: layer_key,
            subLayerKey: TRUSTY_SUBLAYER_GUID,
            weight: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous:
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                        uint64: &weight_value as *const u64 as *mut u64, // TinyWall approach: store millions directly
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
            if let Some((mut blob_ptr, needs_free)) = app_id_blob {
                if needs_free && !blob_ptr.is_null() {
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
    /// use trusty_wfp::{WfpEngine, FilterBuilder, initialize_wfp};
    /// use trusty_domain::RuleDef;
    ///
    /// let engine = WfpEngine::new()?;
    /// initialize_wfp(&engine)?;
    ///
    /// let rule = RuleDef::allow_outbound();
    /// let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
    ///
    /// // Later: remove the filter
    /// FilterBuilder::delete_filter(&engine, filter_id)?;
    /// # Ok::<(), trusty_wfp::WfpError>(())
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
    use trusty_domain::Protocol;

    #[test]
    fn test_layer_selection() {
        assert_eq!(
            FilterBuilder::select_layer(Direction::Outbound, false),
            LAYER_ALE_AUTH_CONNECT_V4
        );
        assert_eq!(
            FilterBuilder::select_layer(Direction::Outbound, true),
            LAYER_ALE_AUTH_CONNECT_V6
        );
        assert_eq!(
            FilterBuilder::select_layer(Direction::Inbound, false),
            LAYER_ALE_AUTH_RECV_ACCEPT_V4
        );
        assert_eq!(
            FilterBuilder::select_layer(Direction::Inbound, true),
            LAYER_ALE_AUTH_RECV_ACCEPT_V6
        );
    }

    #[test]
    fn test_action_translation() {
        assert_eq!(
            FilterBuilder::translate_action(RuleAction::Allow),
            FWP_ACTION_PERMIT
        );
        assert_eq!(
            FilterBuilder::translate_action(RuleAction::Block),
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
    #[ignore] // Requires admin privileges
    fn test_add_simple_filter() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        crate::initialize_wfp(&engine).expect("Failed to initialize WFP");

        let rule = RuleDef::allow_outbound();
        let result = FilterBuilder::add_filter(&engine, &rule);

        assert!(result.is_ok(), "Failed to add filter: {:?}", result);
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_add_and_delete_filter() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        crate::initialize_wfp(&engine).expect("Failed to initialize WFP");

        let rule = RuleDef::allow_outbound();

        // Add filter
        let filter_id = FilterBuilder::add_filter(&engine, &rule).expect("Failed to add filter");

        // Delete filter
        let result = FilterBuilder::delete_filter(&engine, filter_id);

        assert!(result.is_ok(), "Failed to delete filter: {:?}", result);
    }
}
