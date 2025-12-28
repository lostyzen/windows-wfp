//! WFP Network Event Subscription (Learning Mode)
//!
//! Subscribes to WFP network events to monitor blocked connections.
//! Used for learning mode where blocked traffic is logged for auto-whitelisting.

use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmNetEventSubscribe0, FwpmNetEventUnsubscribe0,
    FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_CALLBACK0,
    FWPM_NET_EVENT1,
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, FILETIME};
use windows::core::GUID;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{SystemTime, Duration};
use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use std::sync::mpsc;

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
/// Events are delivered via an mpsc channel for thread-safe processing.
pub struct WfpEventSubscription {
    engine: *const WfpEngine,
    subscription_handle: HANDLE,
    _callback: Box<FWPM_NET_EVENT_CALLBACK0>, // Keep callback alive
    receiver: mpsc::Receiver<NetworkEvent>,
}

impl WfpEventSubscription {
    /// Subscribe to WFP network events
    ///
    /// Creates a new event subscription that monitors network events.
    /// Events are delivered via the returned receiver channel.
    ///
    /// # Errors
    ///
    /// Returns error if subscription fails (permissions, invalid engine, etc.)
    pub fn new(engine: &WfpEngine) -> WfpResult<Self> {
        let (sender, receiver) = mpsc::channel();

        // Box the channel sender so it has a stable address for the context pointer
        let sender_box = Box::new(sender);
        let context = Box::into_raw(sender_box) as *const c_void;

        // Create the callback function
        let callback: FWPM_NET_EVENT_CALLBACK0 = Some(event_callback);

        // Create subscription for all events
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
                // Clean up the boxed sender on error
                let _ = Box::from_raw(context as *mut mpsc::Sender<NetworkEvent>);
                return Err(WfpError::Other(format!(
                    "Failed to subscribe to WFP events: error code {}",
                    result
                )));
            }
        }

        Ok(Self {
            engine: engine as *const WfpEngine,
            subscription_handle,
            _callback: Box::new(callback), // Keep callback alive to prevent GC
            receiver,
        })
    }

    /// Try to receive a network event (non-blocking)
    pub fn try_recv(&self) -> Result<NetworkEvent, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    /// Receive a network event (blocking)
    pub fn recv(&self) -> Result<NetworkEvent, mpsc::RecvError> {
        self.receiver.recv()
    }

    /// Get an iterator over pending events
    pub fn iter(&self) -> mpsc::Iter<'_, NetworkEvent> {
        self.receiver.iter()
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

/// Native callback function invoked by WFP (runs on WFP worker thread)
///
/// # Safety
///
/// This function receives raw pointers from WFP and must carefully:
/// - Validate the event pointer is not null
/// - Parse the FWPM_NET_EVENT1 structure
/// - Send the parsed event to the channel without blocking
unsafe extern "system" fn event_callback(
    context: *mut c_void,
    event_ptr: *const FWPM_NET_EVENT1,
) {
    // Validate pointers
    if context.is_null() || event_ptr.is_null() {
        return;
    }

    // Recover the sender from the context
    let sender = &*(context as *const mpsc::Sender<NetworkEvent>);

    // Parse the event
    let event = &*event_ptr;
    if let Some(network_event) = parse_network_event(event) {
        // Send to channel (non-blocking - drops event if channel is full)
        let _ = sender.send(network_event);
    }
}

/// Parse FWPM_NET_EVENT1 into NetworkEvent
///
/// # Safety
///
/// The event pointer must be valid and point to a complete FWPM_NET_EVENT1 structure.
unsafe fn parse_network_event(event: &FWPM_NET_EVENT1) -> Option<NetworkEvent> {
    let header = &event.header;
    let event_type = NetworkEventType::from(event.r#type.0 as u32);

    // Parse timestamp (FILETIME to SystemTime)
    let timestamp = filetime_to_systemtime(&header.timeStamp);

    // Parse application path (wide string) - appId.data is *mut u8, need to cast
    let app_path = if !header.appId.data.is_null() {
        parse_wide_string(header.appId.data as *const u16)
            .map(PathBuf::from)
    } else {
        None
    };

    // Parse IP addresses based on IP version (ipVersion: 0=V4, 1=V6)
    let (local_addr, remote_addr) = if header.ipVersion.0 == 0 {
        // IPv4
        unsafe {
            let local = parse_ipv4_union(&header.Anonymous1);
            let remote = parse_ipv4_union_remote(&header.Anonymous2);
            (local, remote)
        }
    } else if header.ipVersion.0 == 1 {
        // IPv6
        unsafe {
            let local = parse_ipv6_union(&header.Anonymous1);
            let remote = parse_ipv6_union_remote(&header.Anonymous2);
            (local, remote)
        }
    } else {
        (None, None)
    };

    // Parse filter ID and layer ID for CLASSIFY_DROP events
    let (filter_id, layer_id) = if event_type == NetworkEventType::ClassifyDrop {
        unsafe {
            if !event.Anonymous.classifyDrop.is_null() {
                let drop_info = &*event.Anonymous.classifyDrop;
                (Some(drop_info.filterId), Some(drop_info.layerId))
            } else {
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    Some(NetworkEvent {
        timestamp,
        event_type,
        app_path,
        protocol: header.ipProtocol,
        local_addr,
        remote_addr,
        local_port: header.localPort,
        remote_port: header.remotePort,
        filter_id,
        layer_id,
    })
}

/// Convert FILETIME to SystemTime
fn filetime_to_systemtime(ft: &FILETIME) -> SystemTime {
    // FILETIME is 100-nanosecond intervals since January 1, 1601 (UTC)
    // SystemTime is based on UNIX_EPOCH (January 1, 1970)

    // Difference between Windows epoch (1601) and UNIX epoch (1970) in 100-ns intervals
    const WINDOWS_TO_UNIX_EPOCH: u64 = 116444736000000000;

    let intervals = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);

    if intervals >= WINDOWS_TO_UNIX_EPOCH {
        let unix_intervals = intervals - WINDOWS_TO_UNIX_EPOCH;
        let secs = unix_intervals / 10_000_000;
        let nanos = ((unix_intervals % 10_000_000) * 100) as u32;

        SystemTime::UNIX_EPOCH + Duration::new(secs, nanos)
    } else {
        SystemTime::UNIX_EPOCH
    }
}

/// Parse wide string (null-terminated UTF-16)
unsafe fn parse_wide_string(ptr: *const u16) -> Option<OsString> {
    if ptr.is_null() {
        return None;
    }

    // Find the null terminator
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }

    if len == 0 {
        return None;
    }

    // Convert to OsString
    let slice = std::slice::from_raw_parts(ptr, len);
    Some(OsString::from_wide(slice))
}

/// Parse IPv4 address from union (reads first 4 bytes as u32) - HEADER1_0 version
unsafe fn parse_ipv4_union(addr_union: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_HEADER1_0) -> Option<IpAddr> {
    // Union contains localAddrV4 as u32
    let addr_u32 = addr_union.localAddrV4;
    let bytes = addr_u32.to_ne_bytes();
    Some(IpAddr::V4(Ipv4Addr::from(bytes)))
}

/// Parse IPv6 address from union (reads 16-byte array) - HEADER1_0 version
unsafe fn parse_ipv6_union(addr_union: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_HEADER1_0) -> Option<IpAddr> {
    // Union contains localAddrV6 as byte[16]
    let bytes = addr_union.localAddrV6.byteArray16;
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

/// Parse IPv4 address from remote union (HEADER1_1 version)
unsafe fn parse_ipv4_union_remote(addr_union: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_HEADER1_1) -> Option<IpAddr> {
    let addr_u32 = addr_union.remoteAddrV4;
    let bytes = addr_u32.to_ne_bytes();
    Some(IpAddr::V4(Ipv4Addr::from(bytes)))
}

/// Parse IPv6 address from remote union (HEADER1_1 version)
unsafe fn parse_ipv6_union_remote(addr_union: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_HEADER1_1) -> Option<IpAddr> {
    let bytes = addr_union.remoteAddrV6.byteArray16;
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

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
