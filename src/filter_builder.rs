//! WFP Filter translation from domain RuleDef
//!
//! Translates platform-agnostic RuleDef into WFP FWPM_FILTER0 structures.

use crate::constants::*;
use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterAdd0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT8,
    FWP_ACTION_TYPE, FWPM_FILTER_FLAGS, FWP_BYTE_BLOB_TYPE,
};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::core::{GUID, PWSTR};
use std::net::IpAddr;
use std::ptr;

// Import domain types
use trusty_domain::{RuleDef, Direction, RuleAction, Protocol};

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

    /// Build filter conditions from RuleDef
    ///
    /// Creates condition array based on non-None fields in RuleDef.
    fn build_conditions(rule: &RuleDef) -> WfpResult<Vec<FWPM_FILTER_CONDITION0>> {
        let mut conditions = Vec::new();

        // Condition: APP_ID (application path)
        if let Some(ref app_path) = rule.app_path {
            // Convert path to wide string for WFP
            let path_wide: Vec<u16> = app_path
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        byteBlob: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                            size: (path_wide.len() * 2) as u32,
                            data: path_wide.as_ptr() as *mut u8,
                        } as *const _ as *mut _,
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

        // Condition: REMOTE_IP (TODO: implement IP address conditions)
        // This requires FWP_V4_ADDR_MASK or FWP_V6_ADDR_MASK structures

        Ok(conditions)
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
        let is_ipv6 = rule.remote_ip.as_ref()
            .map(|ip_mask| matches!(ip_mask.addr, IpAddr::V6(_)))
            .unwrap_or(false);

        let layer_key = Self::select_layer(rule.direction, is_ipv6);
        let action = Self::translate_action(rule.action);
        let conditions = Self::build_conditions(rule)?;

        // Convert name to wide string
        let name_wide: Vec<u16> = rule.name.encode_utf16().chain(std::iter::once(0)).collect();

        let filter = FWPM_FILTER0 {
            filterKey: GUID::zeroed(), // Let WFP generate GUID
            displayData: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_wide.as_ptr() as *mut u16),
                description: PWSTR::null(),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &TRUSTY_PROVIDER_GUID as *const _ as *mut _,
            providerData: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            layerKey: layer_key,
            subLayerKey: TRUSTY_SUBLAYER_GUID,
            weight: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                    uint8: (rule.weight / 1_000_000) as u8, // Normalize weight
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

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::FilterAddFailed(format!(
                    "Failed to add filter '{}': error code {}",
                    rule.name, result
                )));
            }
        }

        Ok(filter_id)
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
        assert_eq!(FilterBuilder::translate_action(RuleAction::Allow), FWP_ACTION_PERMIT);
        assert_eq!(FilterBuilder::translate_action(RuleAction::Block), FWP_ACTION_BLOCK);
    }

    #[test]
    fn test_protocol_translation() {
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Tcp), 6);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Udp), 17);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Icmp), 1);
        assert_eq!(FilterBuilder::translate_protocol(Protocol::Icmpv6), 58);
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
}
