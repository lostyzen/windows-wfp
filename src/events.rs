//! WFP Network Event Subscription (Learning Mode)
//!
//! Subscribes to WFP network events to monitor blocked connections.
//! Used for learning mode where blocked traffic is logged for auto-whitelisting.

use crate::app_id::app_id_to_path;
use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::ptr;
use std::sync::mpsc;
use std::time::{Duration, SystemTime};
use windows::core::GUID;
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineGetOption0, FwpmEngineSetOption0, FwpmFreeMemory0, FwpmNetEventSubscribe1,
    FwpmNetEventUnsubscribe0, FWPM_ENGINE_COLLECT_NET_EVENTS,
    FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, FWPM_ENGINE_OPTION, FWPM_NET_EVENT2,
    FWPM_NET_EVENT_FLAG_APP_ID_SET, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET,
    FWPM_NET_EVENT_FLAG_IP_VERSION_SET, FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
    FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW,
    FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE_CAPABILITY_DROP,
    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWP_IP_VERSION_V4,
    FWP_IP_VERSION_V6, FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0,
};

/// Network event from WFP
///
/// Represents a network event captured by the Windows Filtering Platform.
/// Used in learning mode to identify applications that were blocked.
/// Fields are `None` when WFP did not provide the information for this event.
#[derive(Debug, Clone)]
pub struct NetworkEvent {
    /// When the event occurred
    pub timestamp: SystemTime,

    /// Type of event (Classify Drop, Classify Allow, etc.)
    pub event_type: NetworkEventType,

    /// Application path in NT kernel format (e.g. `\device\harddiskvolume3\...\app.exe`)
    pub app_path: Option<PathBuf>,

    /// IP protocol (TCP=6, UDP=17, etc.)
    pub protocol: Option<u8>,

    /// Local IP address
    pub local_addr: Option<IpAddr>,

    /// Remote IP address
    pub remote_addr: Option<IpAddr>,

    /// Local port
    pub local_port: Option<u16>,

    /// Remote port
    pub remote_port: Option<u16>,

    /// Filter ID that triggered the event (ClassifyDrop, ClassifyAllow, CapabilityDrop)
    pub filter_id: Option<u64>,

    /// Layer ID where event occurred (ClassifyDrop, ClassifyAllow)
    pub layer_id: Option<u16>,
}

/// Type of network event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NetworkEventType {
    /// Connection was blocked by a filter
    ClassifyDrop = 3,

    /// Connection was allowed by a filter (only collected when enabled, see
    /// [`WfpEngine::set_classify_allow_events`])
    ClassifyAllow = 6,

    /// App container capability drop
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

impl std::fmt::Display for NetworkEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkEventType::ClassifyDrop => write!(f, "ClassifyDrop"),
            NetworkEventType::ClassifyAllow => write!(f, "ClassifyAllow"),
            NetworkEventType::CapabilityDrop => write!(f, "CapabilityDrop"),
            NetworkEventType::Other(n) => write!(f, "Other({})", n),
        }
    }
}

/// WFP Event Subscription Handle
///
/// RAII wrapper for WFP event subscription. Automatically unsubscribes on drop.
/// Events are delivered via an unbounded mpsc channel.
///
/// The subscription owns a dedicated WFP session, so it is independent of any
/// other [`WfpEngine`] and can be moved freely between threads.
pub struct WfpEventSubscription {
    subscription_handle: HANDLE,
    receiver: mpsc::Receiver<NetworkEvent>,
    /// Boxed `Sender<NetworkEvent>` passed as the WFP callback context; freed after unsubscribing.
    sender_context: *mut c_void,
    engine: WfpEngine,
}

impl WfpEventSubscription {
    /// Subscribe to WFP network events
    ///
    /// Opens a dedicated WFP session and subscribes to network events on it.
    /// Requires administrator privileges.
    ///
    /// # Errors
    ///
    /// Returns error if the session cannot be opened or the subscription fails.
    pub fn new() -> WfpResult<Self> {
        let engine = WfpEngine::new()?;
        let (sender, receiver) = mpsc::channel();

        // Box the channel sender so it has a stable address for the context pointer
        let context = Box::into_raw(Box::new(sender)) as *mut c_void;

        // Create subscription for all events
        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0 {
            enumTemplate: std::ptr::null_mut(), // Subscribe to all events
            flags: 0,
            sessionKey: GUID::zeroed(),
        };

        let mut subscription_handle = HANDLE::default();

        let result = unsafe {
            FwpmNetEventSubscribe1(
                engine.handle(),
                &subscription,
                Some(event_callback),
                Some(context as *const c_void),
                &mut subscription_handle,
            )
        };
        if let Err(err) = WfpError::check("FwpmNetEventSubscribe0", result) {
            drop(unsafe { Box::from_raw(context as *mut mpsc::Sender<NetworkEvent>) });
            return Err(err);
        }

        Ok(Self {
            subscription_handle,
            receiver,
            sender_context: context,
            engine,
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

    /// Blocking iterator over incoming events
    pub fn iter(&self) -> mpsc::Iter<'_, NetworkEvent> {
        self.receiver.iter()
    }
}

impl Drop for WfpEventSubscription {
    fn drop(&mut self) {
        // Runs before `self.engine` is dropped, so the session is still open here.
        if !self.subscription_handle.is_invalid() {
            unsafe {
                // Unsubscribe first so no more callbacks can fire before we free the context
                let _ = FwpmNetEventUnsubscribe0(self.engine.handle(), self.subscription_handle);
            }
        }
        if !self.sender_context.is_null() {
            unsafe {
                drop(Box::from_raw(
                    self.sender_context as *mut mpsc::Sender<NetworkEvent>,
                ));
            }
        }
    }
}

// SAFETY: the subscription owns its WFP session (`WfpEngine` is Send), the subscription
// handle is an opaque kernel handle, and `sender_context` points to a `Sender` (Send) that is
// only freed in `Drop`, after `FwpmNetEventUnsubscribe0` guarantees no callback is running.
unsafe impl Send for WfpEventSubscription {}

// WfpEventSubscription is NOT Sync: the mpsc::Receiver requires exclusive access.

/// Native callback function invoked by WFP (runs on WFP worker thread)
///
/// # Safety
///
/// This function receives raw pointers from WFP and must carefully:
/// - Validate the event pointer is not null
/// - Parse the FWPM_NET_EVENT2 structure
/// - Send the parsed event to the channel without blocking
unsafe extern "system" fn event_callback(context: *mut c_void, event_ptr: *const FWPM_NET_EVENT2) {
    // Validate pointers
    if context.is_null() || event_ptr.is_null() {
        return;
    }

    // Recover the sender from the context
    let sender = &*(context as *const mpsc::Sender<NetworkEvent>);

    // Unbounded channel: never blocks, only fails once the receiver is gone
    let _ = sender.send(parse_network_event(&*event_ptr));
}

/// Parse FWPM_NET_EVENT2 into NetworkEvent, keeping only fields flagged as set
///
/// # Safety
///
/// `event` must be a complete FWPM_NET_EVENT2 provided by WFP (valid pointers).
unsafe fn parse_network_event(event: &FWPM_NET_EVENT2) -> NetworkEvent {
    let header = &event.header;
    let has = |flag: u32| header.flags & flag != 0;

    let app_path = if has(FWPM_NET_EVENT_FLAG_APP_ID_SET) {
        app_id_to_path(&header.appId)
    } else {
        None
    };

    let ip_version = has(FWPM_NET_EVENT_FLAG_IP_VERSION_SET).then_some(header.ipVersion);
    // WFP stores IPv4 addresses as host-order integers
    let local_addr = match (has(FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET), ip_version) {
        (true, Some(FWP_IP_VERSION_V4)) => {
            Some(IpAddr::V4(Ipv4Addr::from(header.Anonymous1.localAddrV4)))
        }
        (true, Some(FWP_IP_VERSION_V6)) => Some(IpAddr::V6(Ipv6Addr::from(
            header.Anonymous1.localAddrV6.byteArray16,
        ))),
        _ => None,
    };
    let remote_addr = match (has(FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET), ip_version) {
        (true, Some(FWP_IP_VERSION_V4)) => {
            Some(IpAddr::V4(Ipv4Addr::from(header.Anonymous2.remoteAddrV4)))
        }
        (true, Some(FWP_IP_VERSION_V6)) => Some(IpAddr::V6(Ipv6Addr::from(
            header.Anonymous2.remoteAddrV6.byteArray16,
        ))),
        _ => None,
    };

    let (filter_id, layer_id) = match event.r#type {
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP if !event.Anonymous.classifyDrop.is_null() => {
            let info = &*event.Anonymous.classifyDrop;
            (Some(info.filterId), Some(info.layerId))
        }
        FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW if !event.Anonymous.classifyAllow.is_null() => {
            let info = &*event.Anonymous.classifyAllow;
            (Some(info.filterId), Some(info.layerId))
        }
        FWPM_NET_EVENT_TYPE_CAPABILITY_DROP if !event.Anonymous.capabilityDrop.is_null() => {
            (Some((*event.Anonymous.capabilityDrop).filterId), None)
        }
        _ => (None, None),
    };

    NetworkEvent {
        timestamp: filetime_to_systemtime(&header.timeStamp),
        event_type: NetworkEventType::from(event.r#type.0 as u32),
        app_path,
        protocol: has(FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET).then_some(header.ipProtocol),
        local_addr,
        remote_addr,
        local_port: has(FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET).then_some(header.localPort),
        remote_port: has(FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET).then_some(header.remotePort),
        filter_id,
        layer_id,
    }
}

impl WfpEngine {
    /// Enable or disable collection of [`NetworkEventType::ClassifyAllow`] events
    ///
    /// Windows does not collect allow events by default. This is a **system-wide,
    /// persistent** BFE setting, not limited to this session; enabling it also
    /// turns on network event collection. Requires administrator privileges.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::Api` if the engine option cannot be read or written.
    pub fn set_classify_allow_events(&self, enabled: bool) -> WfpResult<()> {
        if enabled {
            set_u32_option(self, FWPM_ENGINE_COLLECT_NET_EVENTS, 1)?;
        }
        let keywords = get_u32_option(self, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS)?;
        set_u32_option(
            self,
            FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
            with_flag(keywords, FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW, enabled),
        )
    }
}

fn with_flag(value: u32, flag: u32, enabled: bool) -> u32 {
    if enabled {
        value | flag
    } else {
        value & !flag
    }
}

fn get_u32_option(engine: &WfpEngine, option: FWPM_ENGINE_OPTION) -> WfpResult<u32> {
    let mut value: *mut FWP_VALUE0 = ptr::null_mut();
    let result = unsafe { FwpmEngineGetOption0(engine.handle(), option, &mut value) };
    WfpError::check("FwpmEngineGetOption0", result)?;
    if value.is_null() {
        return Ok(0);
    }

    let current = unsafe {
        if (*value).r#type == FWP_UINT32 {
            (*value).Anonymous.uint32
        } else {
            0
        }
    };
    unsafe { FwpmFreeMemory0(&mut value as *mut *mut FWP_VALUE0 as *mut *mut c_void) };
    Ok(current)
}

fn set_u32_option(engine: &WfpEngine, option: FWPM_ENGINE_OPTION, value: u32) -> WfpResult<()> {
    let value = FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: value },
    };
    let result = unsafe { FwpmEngineSetOption0(engine.handle(), option, &value) };
    WfpError::check("FwpmEngineSetOption0", result)
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_NET_EVENT_CLASSIFY_ALLOW0, FWPM_NET_EVENT_CLASSIFY_DROP2, FWPM_NET_EVENT_TYPE,
    };

    #[test]
    fn test_event_type_conversion() {
        assert_eq!(NetworkEventType::from(3), NetworkEventType::ClassifyDrop);
        assert_eq!(NetworkEventType::from(6), NetworkEventType::ClassifyAllow);
        assert_eq!(NetworkEventType::from(7), NetworkEventType::CapabilityDrop);
        assert_eq!(NetworkEventType::from(99), NetworkEventType::Other(99));
    }

    #[test]
    fn test_event_type_boundaries() {
        assert_eq!(NetworkEventType::from(0), NetworkEventType::Other(0));
        assert_eq!(NetworkEventType::from(2), NetworkEventType::Other(2));
        assert_eq!(NetworkEventType::from(4), NetworkEventType::Other(4));
        assert_eq!(NetworkEventType::from(5), NetworkEventType::Other(5));
        assert_eq!(NetworkEventType::from(8), NetworkEventType::Other(8));
    }

    #[test]
    fn test_filetime_to_systemtime_unix_epoch() {
        // FILETIME for Unix epoch (Jan 1, 1970) = 116444736000000000
        let intervals: u64 = 116444736000000000;
        let ft = FILETIME {
            dwLowDateTime: intervals as u32,
            dwHighDateTime: (intervals >> 32) as u32,
        };
        let result = filetime_to_systemtime(&ft);
        assert_eq!(result, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn test_filetime_to_systemtime_before_unix_epoch() {
        let ft = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        assert_eq!(filetime_to_systemtime(&ft), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn test_filetime_to_systemtime_known_date() {
        // Jan 1, 2000 = 125911584000000000 intervals from Windows epoch
        let intervals: u64 = 125911584000000000;
        let ft = FILETIME {
            dwLowDateTime: intervals as u32,
            dwHighDateTime: (intervals >> 32) as u32,
        };
        let result = filetime_to_systemtime(&ft);
        let duration = result.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(duration.as_secs(), 946684800); // Jan 1, 2000
    }

    fn event(event_type: FWPM_NET_EVENT_TYPE, flags: u32) -> FWPM_NET_EVENT2 {
        let mut event = FWPM_NET_EVENT2 {
            r#type: event_type,
            ..Default::default()
        };
        event.header.flags = flags;
        event
    }

    const ALL_ADDR_FLAGS: u32 = FWPM_NET_EVENT_FLAG_IP_VERSION_SET
        | FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET
        | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET;

    #[test]
    fn test_parse_ipv4_addresses_are_host_order() {
        let mut ev = event(FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, ALL_ADDR_FLAGS);
        ev.header.ipVersion = FWP_IP_VERSION_V4;
        ev.header.Anonymous1.localAddrV4 = 0x0A00_0001;
        ev.header.Anonymous2.remoteAddrV4 = 0x0808_0404;

        let parsed = unsafe { parse_network_event(&ev) };
        assert_eq!(parsed.local_addr, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(parsed.remote_addr, Some("8.8.4.4".parse().unwrap()));
    }

    #[test]
    fn test_parse_ipv6_addresses() {
        let mut ev = event(FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, ALL_ADDR_FLAGS);
        ev.header.ipVersion = FWP_IP_VERSION_V6;
        let remote: Ipv6Addr = "2001:db8::1".parse().unwrap();
        ev.header.Anonymous2.remoteAddrV6.byteArray16 = remote.octets();

        let parsed = unsafe { parse_network_event(&ev) };
        assert_eq!(parsed.local_addr, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert_eq!(parsed.remote_addr, Some(IpAddr::V6(remote)));
    }

    #[test]
    fn test_parse_ignores_fields_without_flags() {
        let mut ev = event(FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, 0);
        ev.header.ipVersion = FWP_IP_VERSION_V4;
        ev.header.Anonymous1.localAddrV4 = 0x0A00_0001;
        ev.header.ipProtocol = 6;
        ev.header.localPort = 1234;
        ev.header.remotePort = 443;
        let mut path: Vec<u8> = "x.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        ev.header.appId.size = path.len() as u32;
        ev.header.appId.data = path.as_mut_ptr();

        let parsed = unsafe { parse_network_event(&ev) };
        assert_eq!(parsed.local_addr, None);
        assert_eq!(parsed.remote_addr, None);
        assert_eq!(parsed.protocol, None);
        assert_eq!(parsed.local_port, None);
        assert_eq!(parsed.remote_port, None);
        assert_eq!(parsed.app_path, None);
    }

    #[test]
    fn test_parse_fields_with_flags() {
        let flags = FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET
            | FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET
            | FWPM_NET_EVENT_FLAG_APP_ID_SET;
        let mut ev = event(FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, flags);
        ev.header.ipProtocol = 6;
        ev.header.localPort = 1234;
        ev.header.remotePort = 443;
        let mut path: Vec<u8> = r"\device\x.exe"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        ev.header.appId.size = path.len() as u32;
        ev.header.appId.data = path.as_mut_ptr();

        let parsed = unsafe { parse_network_event(&ev) };
        assert_eq!(parsed.event_type, NetworkEventType::ClassifyDrop);
        assert_eq!(parsed.protocol, Some(6));
        assert_eq!(parsed.local_port, Some(1234));
        assert_eq!(parsed.remote_port, Some(443));
        assert_eq!(parsed.app_path, Some(PathBuf::from(r"\device\x.exe")));
    }

    #[test]
    fn test_parse_filter_and_layer_ids() {
        let mut drop_info = FWPM_NET_EVENT_CLASSIFY_DROP2 {
            filterId: 42,
            layerId: 7,
            ..Default::default()
        };
        let mut ev = event(FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, 0);
        ev.Anonymous.classifyDrop = &mut drop_info;
        let parsed = unsafe { parse_network_event(&ev) };
        assert_eq!((parsed.filter_id, parsed.layer_id), (Some(42), Some(7)));

        let mut allow_info = FWPM_NET_EVENT_CLASSIFY_ALLOW0 {
            filterId: 43,
            layerId: 8,
            ..Default::default()
        };
        let mut ev = event(FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, 0);
        ev.Anonymous.classifyAllow = &mut allow_info;
        let parsed = unsafe { parse_network_event(&ev) };
        assert_eq!(parsed.event_type, NetworkEventType::ClassifyAllow);
        assert_eq!((parsed.filter_id, parsed.layer_id), (Some(43), Some(8)));

        let ev = event(FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, 0);
        let parsed = unsafe { parse_network_event(&ev) };
        assert_eq!((parsed.filter_id, parsed.layer_id), (None, None));
    }

    #[test]
    fn test_with_flag() {
        assert_eq!(with_flag(0b0001, 0b0100, true), 0b0101);
        assert_eq!(with_flag(0b0101, 0b0100, false), 0b0001);
        assert_eq!(with_flag(0b0101, 0b0100, true), 0b0101);
    }

    #[test]
    #[ignore] // Requires admin privileges; changes a system-wide BFE option
    fn test_set_classify_allow_events_roundtrip() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        let before = get_u32_option(&engine, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS).unwrap();

        engine.set_classify_allow_events(true).unwrap();
        let enabled = get_u32_option(&engine, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS).unwrap();
        assert_ne!(enabled & FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW, 0);

        set_u32_option(&engine, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, before).unwrap();
    }

    #[test]
    fn test_network_event_type_display() {
        assert_eq!(NetworkEventType::ClassifyDrop.to_string(), "ClassifyDrop");
        assert_eq!(NetworkEventType::ClassifyAllow.to_string(), "ClassifyAllow");
        assert_eq!(
            NetworkEventType::CapabilityDrop.to_string(),
            "CapabilityDrop"
        );
        assert_eq!(NetworkEventType::Other(42).to_string(), "Other(42)");
    }
}
