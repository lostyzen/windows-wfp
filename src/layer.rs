//! WFP layer selection and filter weight constants

use crate::constants::*;
use crate::filter::Direction;
use windows::core::GUID;

/// Select the appropriate WFP layer GUID for a given direction and IP version
pub fn select_layer(direction: Direction, is_ipv6: bool) -> GUID {
    match (direction, is_ipv6) {
        (Direction::Outbound, false) => LAYER_ALE_AUTH_CONNECT_V4,
        (Direction::Outbound, true) => LAYER_ALE_AUTH_CONNECT_V6,
        (Direction::Inbound, false) => LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        (Direction::Inbound, true) => LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

/// Standard filter weight (priority) levels
///
/// Higher weight = higher priority (evaluated first by WFP).
///
/// # Examples
///
/// ```
/// use windows_wfp::FilterWeight;
///
/// assert!(FilterWeight::Blocklist.value() > FilterWeight::UserBlock.value());
/// assert!(FilterWeight::UserBlock.value() > FilterWeight::DefaultBlock.value());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum FilterWeight {
    /// Blocklist filters (highest priority, 9M)
    Blocklist = 9_000_000,
    /// Raw socket permit filters (8M)
    RawSocketPermit = 8_000_000,
    /// Raw socket block filters (7M)
    RawSocketBlock = 7_000_000,
    /// User-defined block filters (6M)
    UserBlock = 6_000_000,
    /// User-defined permit filters (5M)
    UserPermit = 5_000_000,
    /// Default permit filter (4M)
    DefaultPermit = 4_000_000,
    /// Default block filter (lowest priority, 3M)
    DefaultBlock = 3_000_000,
}

impl FilterWeight {
    /// Get the numeric weight value as `u64`
    pub fn value(self) -> u64 {
        self as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_selection() {
        assert_eq!(
            select_layer(Direction::Outbound, false),
            LAYER_ALE_AUTH_CONNECT_V4
        );
        assert_eq!(
            select_layer(Direction::Outbound, true),
            LAYER_ALE_AUTH_CONNECT_V6
        );
        assert_eq!(
            select_layer(Direction::Inbound, false),
            LAYER_ALE_AUTH_RECV_ACCEPT_V4
        );
        assert_eq!(
            select_layer(Direction::Inbound, true),
            LAYER_ALE_AUTH_RECV_ACCEPT_V6
        );
    }

    #[test]
    fn test_filter_weight_ordering() {
        assert!(FilterWeight::Blocklist.value() > FilterWeight::RawSocketPermit.value());
        assert!(FilterWeight::UserBlock.value() > FilterWeight::UserPermit.value());
        assert!(FilterWeight::DefaultPermit.value() > FilterWeight::DefaultBlock.value());
    }

    #[test]
    fn test_filter_weight_values() {
        assert_eq!(FilterWeight::Blocklist.value(), 9_000_000);
        assert_eq!(FilterWeight::DefaultBlock.value(), 3_000_000);
    }
}
