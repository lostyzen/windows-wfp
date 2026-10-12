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

use crate::condition::{IpAddrMask, Protocol};
use crate::constants::*;
use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use crate::filter::{Action, FilterRule};
use crate::layer;
use std::ffi::c_void;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FWPM_ACTION0, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAGS,
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE, FWP_MATCH_EQUAL, FWP_UINT16,
    FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK,
    FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};

/// Handle to the WFP filters created from one [`FilterRule`]
///
/// A rule without IP-family-specific conditions is installed on both the IPv4
/// and IPv6 layers, so a single rule may own several WFP filter IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterHandle {
    ids: Vec<u64>,
}

impl FilterHandle {
    /// WFP filter IDs owned by this handle
    pub fn ids(&self) -> &[u64] {
        &self.ids
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn of(ip: &IpAddrMask) -> Self {
        if ip.is_ipv6() {
            IpFamily::V6
        } else {
            IpFamily::V4
        }
    }
}

/// Owned blob returned by `FwpmGetAppIdFromFileName0`, freed on drop
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn from_path(path: &Path) -> WfpResult<Self> {
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
        let result = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path_wide.as_ptr()), &mut blob) };

        if result != ERROR_SUCCESS.0 || blob.is_null() {
            return Err(WfpError::AppPathNotFound(path.display().to_string()));
        }
        Ok(Self(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        unsafe { FwpmFreeMemory0(&mut self.0 as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void) };
    }
}

/// Reject conditions that cannot be translated, instead of silently dropping them
fn check_supported_conditions(rule: &FilterRule) -> WfpResult<()> {
    if rule.service_name.is_some() {
        return Err(WfpError::UnsupportedCondition("service_name".into()));
    }
    if rule.app_container_sid.is_some() {
        return Err(WfpError::UnsupportedCondition("app_container_sid".into()));
    }
    Ok(())
}

/// IP families (and therefore WFP layers) the rule must be installed on
fn target_families(rule: &FilterRule) -> WfpResult<Vec<IpFamily>> {
    let constraints = [
        rule.remote_ip
            .as_ref()
            .map(|ip| (IpFamily::of(ip), "remote IP")),
        rule.local_ip
            .as_ref()
            .map(|ip| (IpFamily::of(ip), "local IP")),
        match rule.protocol {
            Some(Protocol::Icmp) => Some((IpFamily::V4, "ICMP protocol")),
            Some(Protocol::Icmpv6) => Some((IpFamily::V6, "ICMPv6 protocol")),
            _ => None,
        },
    ];

    let mut required: Option<(IpFamily, &str)> = None;
    for (family, source) in constraints.into_iter().flatten() {
        match required {
            Some((other, other_source)) if other != family => {
                return Err(WfpError::InvalidRule(format!(
                    "{source} requires {family:?} but {other_source} requires {other:?}"
                )));
            }
            _ => required = Some((family, source)),
        }
    }

    Ok(match required {
        Some((family, _)) => vec![family],
        None => vec![IpFamily::V4, IpFamily::V6],
    })
}

fn v4_addr_mask(ip: &IpAddrMask) -> Option<FWP_V4_ADDR_AND_MASK> {
    match ip.addr {
        IpAddr::V4(v4) => Some(FWP_V4_ADDR_AND_MASK {
            addr: u32::from(v4),
            mask: FilterBuilder::prefix_to_v4_mask(ip.prefix_len),
        }),
        IpAddr::V6(_) => None,
    }
}

fn v6_addr_mask(ip: &IpAddrMask) -> Option<FWP_V6_ADDR_AND_MASK> {
    match ip.addr {
        IpAddr::V6(v6) => Some(FWP_V6_ADDR_AND_MASK {
            addr: v6.octets(),
            prefixLength: ip.prefix_len,
        }),
        IpAddr::V4(_) => None,
    }
}

fn condition(
    field: GUID,
    data_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: data_type,
            Anonymous: value,
        },
    }
}

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
/// let filter = FilterBuilder::add_filter(&engine, &rule)?;
/// // Later: remove the filter
/// FilterBuilder::delete_filter(&engine, &filter)?;
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
    /// Rules without IPv4/IPv6-specific conditions are installed on both the IPv4
    /// and IPv6 layers so they cannot be bypassed over the other IP family.
    ///
    /// # Errors
    ///
    /// - `WfpError::UnsupportedCondition` if the rule uses a condition not yet translated
    /// - `WfpError::InvalidRule` if the rule mixes IPv4 and IPv6 conditions
    /// - `WfpError::AppPathNotFound` if the application path cannot be resolved
    /// - `WfpError::FilterAddFailed` if WFP rejects the filter
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
    /// let filter = FilterBuilder::add_filter(&engine, &rule)?;
    /// # Ok::<(), windows_wfp::WfpError>(())
    /// ```
    pub fn add_filter(engine: &WfpEngine, rule: &FilterRule) -> WfpResult<FilterHandle> {
        check_supported_conditions(rule)?;
        let families = target_families(rule)?;

        // DOS paths never match in the kernel: WFP needs the NT path produced here.
        let app_id = rule.app_path.as_deref().map(AppId::from_path).transpose()?;

        let mut ids = Vec::with_capacity(families.len());
        for family in families {
            match Self::add_filter_for_family(engine, rule, family, app_id.as_ref()) {
                Ok(id) => ids.push(id),
                Err(err) => {
                    for id in ids {
                        let _ = Self::delete_filter_by_id(engine, id);
                    }
                    return Err(err);
                }
            }
        }

        Ok(FilterHandle { ids })
    }

    fn add_filter_for_family(
        engine: &WfpEngine,
        rule: &FilterRule,
        family: IpFamily,
        app_id: Option<&AppId>,
    ) -> WfpResult<u64> {
        let config = engine.config();
        let layer_key = layer::select_layer(rule.direction, family == IpFamily::V6);

        // Everything referenced by raw pointer below must outlive FwpmFilterAdd0
        let name_wide: Vec<u16> = rule.name.encode_utf16().chain(std::iter::once(0)).collect();
        let weight_value: u64 = rule.weight;
        let remote_v4 = rule.remote_ip.as_ref().and_then(v4_addr_mask);
        let local_v4 = rule.local_ip.as_ref().and_then(v4_addr_mask);
        let remote_v6 = rule.remote_ip.as_ref().and_then(v6_addr_mask);
        let local_v6 = rule.local_ip.as_ref().and_then(v6_addr_mask);

        let mut conditions = Vec::new();

        if let Some(app_id) = app_id {
            conditions.push(condition(
                CONDITION_ALE_APP_ID,
                FWP_BYTE_BLOB_TYPE,
                FWP_CONDITION_VALUE0_0 { byteBlob: app_id.0 },
            ));
        }
        if let Some(port) = rule.remote_port {
            conditions.push(condition(
                CONDITION_IP_REMOTE_PORT,
                FWP_UINT16,
                FWP_CONDITION_VALUE0_0 { uint16: port },
            ));
        }
        if let Some(port) = rule.local_port {
            conditions.push(condition(
                CONDITION_IP_LOCAL_PORT,
                FWP_UINT16,
                FWP_CONDITION_VALUE0_0 { uint16: port },
            ));
        }
        if let Some(protocol) = rule.protocol {
            conditions.push(condition(
                CONDITION_IP_PROTOCOL,
                FWP_UINT8,
                FWP_CONDITION_VALUE0_0 {
                    uint8: Self::translate_protocol(protocol),
                },
            ));
        }
        for (field, mask) in [
            (CONDITION_IP_REMOTE_ADDRESS, &remote_v4),
            (CONDITION_IP_LOCAL_ADDRESS, &local_v4),
        ] {
            if let Some(mask) = mask {
                conditions.push(condition(
                    field,
                    FWP_V4_ADDR_MASK,
                    FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: mask as *const _ as *mut _,
                    },
                ));
            }
        }
        for (field, mask) in [
            (CONDITION_IP_REMOTE_ADDRESS, &remote_v6),
            (CONDITION_IP_LOCAL_ADDRESS, &local_v6),
        ] {
            if let Some(mask) = mask {
                conditions.push(condition(
                    field,
                    FWP_V6_ADDR_MASK,
                    FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: mask as *const _ as *mut _,
                    },
                ));
            }
        }

        let filter = FWPM_FILTER0 {
            filterKey: GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_wide.as_ptr() as *mut u16),
                description: PWSTR::null(),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &config.provider_key as *const GUID as *mut GUID,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            layerKey: layer_key,
            subLayerKey: config.sublayer_key,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &weight_value as *const u64 as *mut u64,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                ptr::null_mut()
            } else {
                conditions.as_ptr() as *mut _
            },
            action: FWPM_ACTION0 {
                r#type: Self::translate_action(rule.action),
                Anonymous: Default::default(),
            },
            Anonymous: Default::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: Default::default(),
        };

        let mut filter_id: u64 = 0;
        let result =
            unsafe { FwpmFilterAdd0(engine.handle(), &filter, None, Some(&mut filter_id)) };

        if result != ERROR_SUCCESS.0 {
            return Err(WfpError::FilterAddFailed(format!(
                "Failed to add filter '{}' ({:?} layer): error code {}",
                rule.name, family, result
            )));
        }

        Ok(filter_id)
    }

    /// Delete all WFP filters owned by a [`FilterHandle`]
    ///
    /// Attempts to delete every filter even if one deletion fails, and returns
    /// the first error encountered.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::FilterDeleteFailed` if a filter cannot be deleted.
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
    /// let filter = FilterBuilder::add_filter(&engine, &rule)?;
    ///
    /// // Later: remove the filter
    /// FilterBuilder::delete_filter(&engine, &filter)?;
    /// # Ok::<(), windows_wfp::WfpError>(())
    /// ```
    pub fn delete_filter(engine: &WfpEngine, filter: &FilterHandle) -> WfpResult<()> {
        let mut first_error = None;
        for &id in &filter.ids {
            if let Err(err) = Self::delete_filter_by_id(engine, id) {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Delete a single WFP filter by ID (e.g. one found with [`FilterEnumerator`](crate::FilterEnumerator))
    ///
    /// # Errors
    ///
    /// Returns `WfpError::FilterDeleteFailed` if the filter cannot be deleted.
    pub fn delete_filter_by_id(engine: &WfpEngine, filter_id: u64) -> WfpResult<()> {
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
    use crate::filter::{Action, Direction, FilterRule};

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

    fn rule() -> FilterRule {
        FilterRule::new("Test", Direction::Outbound, Action::Block)
    }

    fn cidr(s: &str) -> IpAddrMask {
        IpAddrMask::from_cidr(s).unwrap()
    }

    #[test]
    fn test_service_name_is_rejected() {
        let result = check_supported_conditions(&rule().with_service_name("dnscache"));
        assert!(matches!(result, Err(WfpError::UnsupportedCondition(c)) if c == "service_name"));
    }

    #[test]
    fn test_app_container_sid_is_rejected() {
        let result = check_supported_conditions(&rule().with_app_container_sid("S-1-15-2-1"));
        assert!(
            matches!(result, Err(WfpError::UnsupportedCondition(c)) if c == "app_container_sid")
        );
    }

    #[test]
    fn test_supported_conditions_are_accepted() {
        let rule = rule()
            .with_app_path(r"C:\test.exe")
            .with_protocol(Protocol::Tcp)
            .with_remote_port(443)
            .with_remote_ip(cidr("10.0.0.0/8"));
        assert!(check_supported_conditions(&rule).is_ok());
    }

    #[test]
    fn test_rule_without_ip_targets_both_families() {
        let families = target_families(&rule().with_app_path(r"C:\test.exe")).unwrap();
        assert_eq!(families, vec![IpFamily::V4, IpFamily::V6]);

        let families = target_families(&rule().with_protocol(Protocol::Tcp)).unwrap();
        assert_eq!(families, vec![IpFamily::V4, IpFamily::V6]);
    }

    #[test]
    fn test_ip_conditions_select_single_family() {
        let v4 = target_families(&rule().with_remote_ip(cidr("1.1.1.1/32"))).unwrap();
        assert_eq!(v4, vec![IpFamily::V4]);

        let v6 = target_families(&rule().with_local_ip(cidr("::1/128"))).unwrap();
        assert_eq!(v6, vec![IpFamily::V6]);

        let both_v4 = target_families(
            &rule()
                .with_remote_ip(cidr("1.1.1.1/32"))
                .with_local_ip(cidr("10.0.0.0/8")),
        )
        .unwrap();
        assert_eq!(both_v4, vec![IpFamily::V4]);
    }

    #[test]
    fn test_icmp_protocols_select_family() {
        let v4 = target_families(&rule().with_protocol(Protocol::Icmp)).unwrap();
        assert_eq!(v4, vec![IpFamily::V4]);

        let v6 = target_families(&rule().with_protocol(Protocol::Icmpv6)).unwrap();
        assert_eq!(v6, vec![IpFamily::V6]);
    }

    #[test]
    fn test_mixed_families_are_rejected() {
        let mixed_ips = rule()
            .with_remote_ip(cidr("1.1.1.1/32"))
            .with_local_ip(cidr("::1/128"));
        assert!(matches!(
            target_families(&mixed_ips),
            Err(WfpError::InvalidRule(_))
        ));

        let icmp_v6_ip = rule()
            .with_protocol(Protocol::Icmp)
            .with_remote_ip(cidr("2001:db8::/32"));
        assert!(matches!(
            target_families(&icmp_v6_ip),
            Err(WfpError::InvalidRule(_))
        ));
    }

    #[test]
    fn test_addr_masks_match_family() {
        let v4 = cidr("192.168.1.0/24");
        let mask = v4_addr_mask(&v4).unwrap();
        assert_eq!(mask.addr, 0xC0A80100);
        assert_eq!(mask.mask, 0xFFFFFF00);
        assert!(v6_addr_mask(&v4).is_none());

        let v6 = cidr("2001:db8::/32");
        let mask = v6_addr_mask(&v6).unwrap();
        assert_eq!(mask.prefixLength, 32);
        assert_eq!(mask.addr[..4], [0x20, 0x01, 0x0d, 0xb8]);
        assert!(v4_addr_mask(&v6).is_none());
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

        let filter = FilterBuilder::add_filter(&engine, &rule).expect("Failed to add filter");
        assert_eq!(
            filter.ids().len(),
            2,
            "Expected one IPv4 and one IPv6 filter"
        );
        let result = FilterBuilder::delete_filter(&engine, &filter);

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
