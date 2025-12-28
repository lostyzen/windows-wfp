//! WFP Network Event Subscription (Learning Mode)
//!
//! Subscribes to WFP network events to monitor blocked connections.
//! Used for learning mode where blocked traffic is logged for auto-whitelisting.

use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmNetEventSubscribe0, FwpmNetEventUnsubscribe0,
    FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_CALLBACK0,
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::core::GUID;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;
use std::ffi::c_void;

/// Network event from WFP
///
/// Represents a network event captured by the Windows Filtering Platform.
/// Used in learning mode to identify applications that were blocked.
#[derive(Debug, Clone)]
pub struct NetworkEvent {
    /// When the event occurred
    pub timestamp: SystemTime,

    /// Type of event (Classify Drop, Classify Allow, etc.)
    pub event_type: NetworkEventType,

    /// Application path that triggered the event (if available)
    pub app_path: Option<PathBuf>,

    /// IP protocol (TCP=6, UDP=17, etc.)
    pub protocol: u8,

    /// Local IP address
    pub local_addr: Option<IpAddr>,

    /// Remote IP address
    pub remote_addr: Option<IpAddr>,

    /// Local port
    pub local_port: u16,

    /// Remote port
    pub remote_port: u16,

    /// Filter ID that triggered the event (for CLASSIFY_DROP)
    pub filter_id: Option<u64>,

    /// Layer ID where event occurred
    pub layer_id: Option<u16>,
}

/// Type of network event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NetworkEventType {
    /// Connection was blocked by a filter
    ClassifyDrop = 3,

    /// Connection was allowed by a filter (Win8+)
    ClassifyAllow = 6,

    /// App container capability drop (Win8+)
    CapabilityDrop = 7,

    /// Other event type
    Other(u32),
}

impl From<u32> for NetworkEventType {
    fn from(value: u32) -> Self {
        match value {
            3 => NetworkEventType::ClassifyDrop,
            6 => NetworkEventType::ClassifyAllow,
            7 => NetworkEventType::CapabilityDrop,
            other => NetworkEventType::Other(other),
        }
    }
}

/// WFP Event Subscription Handle
///
/// RAII wrapper for WFP event subscription. Automatically unsubscribes on drop.
pub struct WfpEventSubscription {
    engine: *const WfpEngine,
    subscription_handle: HANDLE,
}

impl WfpEventSubscription {
    /// Subscribe to WFP network events
    ///
    /// Creates a new event subscription that monitors network events.
    /// Events are delivered via the callback function.
    ///
    /// # Safety
    ///
    /// The callback function will be called from a WFP worker thread.
    /// It must be thread-safe and must not block for long periods.
    ///
    /// # Errors
    ///
    /// Returns error if subscription fails (permissions, invalid engine, etc.)
    pub fn new(
        engine: &WfpEngine,
        callback: FWPM_NET_EVENT_CALLBACK0,
        context: *const c_void,
    ) -> WfpResult<Self> {
        // Create subscription for CLASSIFY_DROP events
        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0 {
            enumTemplate: std::ptr::null_mut(), // Subscribe to all events
            flags: 0,
            sessionKey: GUID::zeroed(),
        };

        let mut subscription_handle = HANDLE::default();

        unsafe {
            let result = FwpmNetEventSubscribe0(
                engine.handle(),
                &subscription,
                callback,
                Some(context),
                &mut subscription_handle,
            );

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::Other(format!(
                    "Failed to subscribe to WFP events: error code {}",
                    result
                )));
            }
        }

        Ok(Self {
            engine: engine as *const WfpEngine,
            subscription_handle,
        })
    }
}

impl Drop for WfpEventSubscription {
    fn drop(&mut self) {
        if !self.subscription_handle.is_invalid() && !self.engine.is_null() {
            unsafe {
                let _ = FwpmNetEventUnsubscribe0(
                    (*self.engine).handle(),
                    self.subscription_handle,
                );
            }
        }
    }
}

// Note: Callback implementation will be added in next iteration
// This requires careful handling of C callbacks -> Rust closures
// and thread-safe event delivery (mpsc channel)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_conversion() {
        assert_eq!(NetworkEventType::from(3), NetworkEventType::ClassifyDrop);
        assert_eq!(NetworkEventType::from(6), NetworkEventType::ClassifyAllow);
        assert_eq!(NetworkEventType::from(7), NetworkEventType::CapabilityDrop);
        assert_eq!(NetworkEventType::from(99), NetworkEventType::Other(99));
    }
}
