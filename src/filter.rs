//! WFP filter rule definition
//!
//! Platform-specific filter rule that maps directly to WFP concepts.
//! This is the main input type for [`FilterBuilder::add_filter`](crate::FilterBuilder::add_filter).

use crate::condition::{IpAddrMask, Protocol};
use crate::layer::FilterWeight;
use std::path::PathBuf;

/// Direction of network traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Traffic coming from the network to the local machine
    Inbound,
    /// Traffic initiated by the local machine going out
    Outbound,
}

/// Action to take when a filter matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Allow the traffic through
    Permit,
    /// Block the traffic
    Block,
}

/// A WFP filter rule definition
///
/// Describes a firewall filter to be applied via the Windows Filtering Platform.
/// All condition fields are optional — omitting a condition means "match all" for that field.
///
/// # Examples
///
/// ```
/// use windows_wfp::{FilterRule, Direction, Action, FilterWeight};
/// use std::path::PathBuf;
///
/// // Block all outbound traffic from curl.exe
/// let rule = FilterRule::new("Block curl", Direction::Outbound, Action::Block)
///     .with_weight(FilterWeight::UserBlock)
///     .with_app_path(r"C:\Windows\System32\curl.exe");
///
/// // Allow all outbound traffic (no conditions = match all)
/// let allow_all = FilterRule::new("Allow all", Direction::Outbound, Action::Permit)
///     .with_weight(FilterWeight::DefaultPermit);
/// ```
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// Human-readable rule name (displayed in WFP management tools)
    pub name: String,
    /// Traffic direction
    pub direction: Direction,
    /// Action to take (permit or block)
    pub action: Action,
    /// Filter priority (higher weight = evaluated first)
    pub weight: u64,
    /// Application executable path (auto-converted to NT kernel path)
    pub app_path: Option<PathBuf>,
    /// Windows service name (matched via service SID)
    pub service_name: Option<String>,
    /// AppContainer SID (for UWP/packaged apps)
    pub app_container_sid: Option<String>,
    /// Local IP address with CIDR mask
    pub local_ip: Option<IpAddrMask>,
    /// Remote IP address with CIDR mask
    pub remote_ip: Option<IpAddrMask>,
    /// Local port number (1-65535)
    pub local_port: Option<u16>,
    /// Remote port number (1-65535)
    pub remote_port: Option<u16>,
    /// IP protocol (TCP, UDP, ICMP, etc.)
    pub protocol: Option<Protocol>,
}

impl FilterRule {
    /// Create a new filter rule with required fields
    pub fn new(name: impl Into<String>, direction: Direction, action: Action) -> Self {
        Self {
            name: name.into(),
            direction,
            action,
            weight: FilterWeight::UserPermit.value(),
            app_path: None,
            service_name: None,
            app_container_sid: None,
            local_ip: None,
            remote_ip: None,
            local_port: None,
            remote_port: None,
            protocol: None,
        }
    }

    /// Set the filter weight (priority)
    pub fn with_weight(mut self, weight: FilterWeight) -> Self {
        self.weight = weight.value();
        self
    }

    /// Set a raw weight value
    pub fn with_raw_weight(mut self, weight: u64) -> Self {
        self.weight = weight;
        self
    }

    /// Set the application path to filter
    pub fn with_app_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.app_path = Some(path.into());
        self
    }

    /// Set the protocol to filter
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Set the remote port to filter
    pub fn with_remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }

    /// Set the local port to filter
    pub fn with_local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    /// Set the remote IP address with CIDR mask
    pub fn with_remote_ip(mut self, ip: IpAddrMask) -> Self {
        self.remote_ip = Some(ip);
        self
    }

    /// Set the local IP address with CIDR mask
    pub fn with_local_ip(mut self, ip: IpAddrMask) -> Self {
        self.local_ip = Some(ip);
        self
    }

    /// Set the Windows service name
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = Some(name.into());
        self
    }

    /// Set the AppContainer SID
    pub fn with_app_container_sid(mut self, sid: impl Into<String>) -> Self {
        self.app_container_sid = Some(sid.into());
        self
    }

    /// Block all outbound traffic (no conditions)
    pub fn block_all_outbound() -> Self {
        Self::new("Block All Outbound", Direction::Outbound, Action::Block)
            .with_weight(FilterWeight::Blocklist)
    }

    /// Allow all outbound traffic (no conditions)
    pub fn allow_all_outbound() -> Self {
        Self::new("Allow All Outbound", Direction::Outbound, Action::Permit)
            .with_weight(FilterWeight::DefaultPermit)
    }

    /// Block all inbound traffic (no conditions)
    pub fn block_all_inbound() -> Self {
        Self::new("Block All Inbound", Direction::Inbound, Action::Block)
            .with_weight(FilterWeight::DefaultBlock)
    }

    /// Default block rule (lowest priority catch-all)
    pub fn default_block() -> Self {
        Self::new("Default Block", Direction::Outbound, Action::Block)
            .with_weight(FilterWeight::DefaultBlock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_filter_rule_defaults() {
        let rule = FilterRule::new("Test", Direction::Outbound, Action::Block);
        assert_eq!(rule.name, "Test");
        assert_eq!(rule.direction, Direction::Outbound);
        assert_eq!(rule.action, Action::Block);
        assert_eq!(rule.weight, FilterWeight::UserPermit.value());
        assert!(rule.app_path.is_none());
        assert!(rule.protocol.is_none());
    }

    #[test]
    fn test_builder_pattern() {
        let rule = FilterRule::new("Block curl", Direction::Outbound, Action::Block)
            .with_weight(FilterWeight::UserBlock)
            .with_app_path(r"C:\Windows\System32\curl.exe")
            .with_protocol(Protocol::Tcp)
            .with_remote_port(443);

        assert_eq!(rule.weight, FilterWeight::UserBlock.value());
        assert_eq!(rule.protocol, Some(Protocol::Tcp));
        assert_eq!(rule.remote_port, Some(443));
    }

    #[test]
    fn test_convenience_constructors() {
        let block = FilterRule::block_all_outbound();
        assert_eq!(block.action, Action::Block);
        assert_eq!(block.weight, FilterWeight::Blocklist.value());

        let allow = FilterRule::allow_all_outbound();
        assert_eq!(allow.action, Action::Permit);

        let default = FilterRule::default_block();
        assert_eq!(default.weight, FilterWeight::DefaultBlock.value());
    }

    #[test]
    fn test_with_raw_weight() {
        let rule = FilterRule::new("Custom", Direction::Outbound, Action::Permit)
            .with_raw_weight(42_000_000);
        assert_eq!(rule.weight, 42_000_000);
    }

    #[test]
    fn test_with_ip_conditions() {
        use std::net::IpAddr;
        let rule = FilterRule::new("IP filter", Direction::Outbound, Action::Block)
            .with_remote_ip(IpAddrMask::new(
                "192.168.1.0".parse::<IpAddr>().unwrap(),
                24,
            ))
            .with_local_ip(IpAddrMask::new("10.0.0.1".parse::<IpAddr>().unwrap(), 32));

        assert!(rule.remote_ip.is_some());
        assert_eq!(rule.remote_ip.as_ref().unwrap().prefix_len, 24);
    }

    #[test]
    fn test_with_service_name() {
        let rule = FilterRule::new("Svc filter", Direction::Outbound, Action::Permit)
            .with_service_name("dnscache");
        assert_eq!(rule.service_name.as_deref(), Some("dnscache"));
    }

    #[test]
    fn test_with_app_container_sid() {
        let rule = FilterRule::new("UWP filter", Direction::Outbound, Action::Permit)
            .with_app_container_sid("S-1-15-2-1234");
        assert_eq!(rule.app_container_sid.as_deref(), Some("S-1-15-2-1234"));
    }

    #[test]
    fn test_with_local_port() {
        let rule = FilterRule::new("Port filter", Direction::Inbound, Action::Permit)
            .with_local_port(8080);
        assert_eq!(rule.local_port, Some(8080));
    }

    #[test]
    fn test_block_all_inbound() {
        let rule = FilterRule::block_all_inbound();
        assert_eq!(rule.direction, Direction::Inbound);
        assert_eq!(rule.action, Action::Block);
        assert_eq!(rule.weight, FilterWeight::DefaultBlock.value());
    }

    #[test]
    fn test_all_defaults_none() {
        let rule = FilterRule::new("Empty", Direction::Outbound, Action::Permit);
        assert!(rule.app_path.is_none());
        assert!(rule.service_name.is_none());
        assert!(rule.app_container_sid.is_none());
        assert!(rule.local_ip.is_none());
        assert!(rule.remote_ip.is_none());
        assert!(rule.local_port.is_none());
        assert!(rule.remote_port.is_none());
        assert!(rule.protocol.is_none());
    }

    #[test]
    fn test_full_builder_chain() {
        use std::net::IpAddr;
        let rule = FilterRule::new("Full", Direction::Outbound, Action::Block)
            .with_weight(FilterWeight::UserBlock)
            .with_app_path(r"C:\test.exe")
            .with_protocol(Protocol::Tcp)
            .with_remote_port(443)
            .with_local_port(0)
            .with_remote_ip(IpAddrMask::new("1.1.1.1".parse::<IpAddr>().unwrap(), 32))
            .with_local_ip(IpAddrMask::new("10.0.0.1".parse::<IpAddr>().unwrap(), 32))
            .with_service_name("svc")
            .with_app_container_sid("sid");

        assert_eq!(rule.name, "Full");
        assert!(rule.app_path.is_some());
        assert_eq!(rule.protocol, Some(Protocol::Tcp));
        assert_eq!(rule.remote_port, Some(443));
        assert_eq!(rule.local_port, Some(0));
        assert!(rule.remote_ip.is_some());
        assert!(rule.local_ip.is_some());
        assert_eq!(rule.service_name.as_deref(), Some("svc"));
        assert_eq!(rule.app_container_sid.as_deref(), Some("sid"));
    }

    #[test]
    fn test_direction_copy_eq() {
        let d1 = Direction::Outbound;
        let d2 = d1; // Copy
        assert_eq!(d1, d2);
        assert_ne!(Direction::Inbound, Direction::Outbound);
    }

    #[test]
    fn test_action_copy_eq() {
        let a1 = Action::Permit;
        let a2 = a1; // Copy
        assert_eq!(a1, a2);
        assert_ne!(Action::Permit, Action::Block);
    }
}
