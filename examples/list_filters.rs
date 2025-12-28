//! List all WFP filters
//!
//! This example enumerates and displays all active WFP filters in the system.
//! Useful for debugging and seeing what TinyWall and other firewalls are doing.
//!
//! # Usage
//!
//! **REQUIRES ADMINISTRATOR PRIVILEGES**
//!
//! ```bash
//! cargo run --example list_filters --release
//! ```

use trusty_wfp::{WfpEngine, WfpResult};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterEnum0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0,
    FWPM_FILTER0,
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use std::ptr;

fn main() -> WfpResult<()> {
    println!("🔍 TRusTY Wall - WFP Filter Enumeration\n");

    // Open WFP engine
    println!("📡 Opening WFP Engine...");
    let engine = WfpEngine::new()?;
    println!("✓ Engine opened\n");

    // Create enumeration handle
    let mut enum_handle = HANDLE::default();

    unsafe {
        // Pass NULL template to enumerate ALL filters
        let result = FwpmFilterCreateEnumHandle0(
            engine.handle(),
            None, // NULL template = enumerate all filters
            &mut enum_handle,
        );

        if result != ERROR_SUCCESS.0 {
            eprintln!("Failed to create enum handle: error {} (0x{:X})", result, result);
            return Ok(());
        }
    }

    println!("📋 Enumerating WFP filters...\n");
    println!("{:-<180}", "");
    println!("{:<10} {:<40} {:<15} {:<15} {:<15} {:<60}", "Filter ID", "Name", "Action", "Provider", "Weight", "App Path");
    println!("{:-<180}", "");

    let mut total_filters = 0;
    let mut trusty_filters = 0;
    let mut page = 0;

    loop {
        let mut filters: *mut *mut FWPM_FILTER0 = ptr::null_mut();
        let mut num_returned: u32 = 0;

        unsafe {
            let result = FwpmFilterEnum0(
                engine.handle(),
                enum_handle,
                100, // Request 100 filters at a time
                &mut filters,
                &mut num_returned,
            );

            if result != ERROR_SUCCESS.0 {
                break;
            }

            if num_returned == 0 {
                break;
            }

            page += 1;

            // Process returned filters
            for i in 0..num_returned {
                let filter = &**filters.offset(i as isize);

                // Get filter name
                let name = if !filter.displayData.name.is_null() {
                    filter.displayData.name.to_string().unwrap_or_else(|_| "Unknown".to_string())
                } else {
                    "Unknown".to_string()
                };

                // Get action - FWP_ACTION_TYPE: 0x1=BLOCK, 0x2=PERMIT, 0x4=CALLOUT
                let action = match filter.action.r#type {
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_BLOCK => "BLOCK",
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_PERMIT => "PERMIT",
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_CALLOUT_TERMINATING => "CALLOUT_TERM",
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_CALLOUT_INSPECTION => "CALLOUT_INSP",
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_CALLOUT_UNKNOWN => "CALLOUT_UNK",
                    _ => "OTHER",
                };

                // Get provider name by reading providerKey GUID
                let provider = if !filter.providerKey.is_null() {
                    let provider_guid = &*filter.providerKey;
                    // TinyWall GUID: check if it matches known GUIDs
                    format!("{:?}", provider_guid)
                        .chars()
                        .take(12)
                        .collect::<String>()
                } else {
                    "System".to_string()
                };

                // Check if it's our filter
                let is_trusty = name.contains("TRusTY") || name.contains("Block curl") || name.contains("Block Notepad");
                if is_trusty {
                    trusty_filters += 1;
                }

                // Get weight - FWP_VALUE0 can have different types
                let weight = match filter.weight.r#type {
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8 => {
                        filter.weight.Anonymous.uint8 as u64
                    }
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT16 => {
                        filter.weight.Anonymous.uint16 as u64
                    }
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT32 => {
                        filter.weight.Anonymous.uint32 as u64
                    }
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT64 => {
                        *filter.weight.Anonymous.uint64
                    }
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_EMPTY => 0,
                    _ => 0,
                };

                // Format name with truncation (char-boundary safe)
                let display_name = if name.chars().count() > 40 {
                    let truncated: String = name.chars().take(37).collect();
                    format!("{}...", truncated)
                } else {
                    name.clone()
                };

                // Extract APP_ID (application path) from filter conditions
                let app_path = if filter.numFilterConditions > 0 && !filter.filterCondition.is_null() {
                    let conditions = std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize);

                    // Look for FWPM_CONDITION_ALE_APP_ID
                    conditions.iter()
                        .find(|c| {
                            let guid = &c.fieldKey;
                            // FWPM_CONDITION_ALE_APP_ID = {d78e1e87-8644-4ea5-9437-d809ecefc971}
                            format!("{:?}", guid).to_lowercase().contains("d78e1e87")
                        })
                        .and_then(|condition| {
                            // APP_ID is a FWP_BYTE_BLOB_TYPE
                            if condition.conditionValue.r#type == windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB_TYPE {
                                let blob = &*condition.conditionValue.Anonymous.byteBlob;
                                if !blob.data.is_null() && blob.size > 0 {
                                    // APP_ID is a wide string
                                    let wide_slice = std::slice::from_raw_parts(
                                        blob.data as *const u16,
                                        (blob.size / 2) as usize
                                    );
                                    // Find null terminator
                                    let null_pos = wide_slice.iter().position(|&c| c == 0).unwrap_or(wide_slice.len());
                                    String::from_utf16(&wide_slice[..null_pos]).ok()
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| String::new())
                } else {
                    String::new()
                };

                // Truncate app path for display (char-boundary safe)
                let display_path = if app_path.chars().count() > 60 {
                    let chars: Vec<char> = app_path.chars().collect();
                    let start_idx = chars.len().saturating_sub(57);
                    let truncated: String = chars[start_idx..].iter().collect();
                    format!("...{}", truncated)
                } else {
                    app_path.clone()
                };

                // Highlight our filters
                if is_trusty {
                    println!("\x1b[32m{:<10} {:<40} {:<15} {:<15} {:<15} {:<60}\x1b[0m",
                        filter.filterId,
                        display_name,
                        action,
                        provider,
                        weight,
                        display_path
                    );
                } else {
                    println!("{:<10} {:<40} {:<15} {:<15} {:<15} {:<60}",
                        filter.filterId,
                        display_name,
                        action,
                        provider,
                        weight,
                        display_path
                    );
                }

                total_filters += 1;
            }

            // Free the returned array - FwpmFreeMemory0 expects void**
            if !filters.is_null() {
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFreeMemory0(
                    &mut filters as *mut _ as *mut *mut _
                );
            }
        }
    }

    println!("{:-<180}", "");
    println!("\n📊 Summary:");
    println!("   Total filters: {}", total_filters);
    println!("   TRusTY Wall filters: {}", trusty_filters);
    println!("   Pages enumerated: {}", page);

    // Cleanup
    unsafe {
        let _ = FwpmFilterDestroyEnumHandle0(engine.handle(), enum_handle);
    }

    println!("\n✨ Enumeration complete!");
    Ok(())
}
