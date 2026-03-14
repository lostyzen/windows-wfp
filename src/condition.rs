//! WFP filter condition types
//!
//! Types used as filter conditions in WFP rules: IP addresses with masks,
//! and IP protocol numbers.

use std::fmt;
use std::net::IpAddr;

/// IP address with CIDR prefix length
///
/// Used for local and remote IP address conditions in WFP filters.
///
/// # Examples
///
/// ```
/// use windows_wfp::IpAddrMask;
/// use std::net::IpAddr;
///
/// // Match a single host
/// let host = IpAddrMask::new("192.168.1.1".parse().unwrap(), 32);
///
/// // Match a /24 subnet
/// let subnet = IpAddrMask::from_cidr("192.168.1.0/24").unwrap();
///
/// // Match an IPv6 address
/// let ipv6 = IpAddrMask::new("::1".parse().unwrap(), 128);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddrMask {
    /// IP address (IPv4 or IPv6)
    pub addr: IpAddr,
    /// CIDR prefix length (0-32 for IPv4, 0-128 for IPv6)
    pub prefix_len: u8,
}

impl IpAddrMask {
    /// Create a new IP address with mask
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }

    /// Parse from CIDR notation (e.g., "192.168.1.0/24" or "::1/128")
    ///
    /// # Errors
    ///
    /// Returns an error string if the format is invalid.
    pub fn from_cidr(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR notation: {}", s));
        }

        let addr: IpAddr = parts[0]
            .parse()
            .map_err(|e| format!("Invalid IP address: {}", e))?;

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|e| format!("Invalid prefix length: {}", e))?;

        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_len > max_prefix {
            return Err(format!(
                "Prefix length {} exceeds maximum {} for {:?}",
                prefix_len, max_prefix, addr
            ));
        }

        Ok(Self { addr, prefix_len })
    }

    /// Returns true if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self.addr, IpAddr::V6(_))
    }
}

/// IP protocol numbers (IANA assigned)
///
/// Standard protocol numbers used in WFP filter conditions.
/// Values match the IANA protocol number assignments.
///
/// # Examples
///
/// ```
/// use windows_wfp::Protocol;
///
/// let tcp = Protocol::Tcp;
/// assert_eq!(tcp as u8, 6);
///
/// let udp = Protocol::Udp;
/// assert_eq!(udp as u8, 17);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Protocol {
    /// IPv6 Hop-by-Hop Option (protocol 0)
    Hopopt = 0,
    /// Internet Control Message Protocol v4 (protocol 1)
    Icmp = 1,
    /// Internet Group Management Protocol (protocol 2)
    Igmp = 2,
    /// Transmission Control Protocol (protocol 6)
    Tcp = 6,
    /// User Datagram Protocol (protocol 17)
    Udp = 17,
    /// Generic Routing Encapsulation (protocol 47)
    Gre = 47,
    /// Encapsulating Security Payload / IPsec (protocol 50)
    Esp = 50,
    /// Authentication Header / IPsec (protocol 51)
    Ah = 51,
    /// Internet Control Message Protocol v6 (protocol 58)
    Icmpv6 = 58,
}

impl Protocol {
    /// Get the IANA protocol number
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Hopopt => write!(f, "HOPOPT"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Gre => write!(f, "GRE"),
            Protocol::Esp => write!(f, "ESP"),
            Protocol::Ah => write!(f, "AH"),
            Protocol::Icmpv6 => write!(f, "ICMPv6"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_addr_mask_new() {
        let mask = IpAddrMask::new("10.0.0.1".parse().unwrap(), 24);
        assert_eq!(mask.prefix_len, 24);
        assert!(!mask.is_ipv6());
    }

    #[test]
    fn test_ip_addr_mask_from_cidr_v4() {
        let mask = IpAddrMask::from_cidr("192.168.1.0/24").unwrap();
        assert_eq!(mask.addr, "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(mask.prefix_len, 24);
    }

    #[test]
    fn test_ip_addr_mask_from_cidr_v6() {
        let mask = IpAddrMask::from_cidr("fe80::1/64").unwrap();
        assert!(mask.is_ipv6());
        assert_eq!(mask.prefix_len, 64);
    }

    #[test]
    fn test_ip_addr_mask_invalid_cidr() {
        assert!(IpAddrMask::from_cidr("not-an-ip/24").is_err());
        assert!(IpAddrMask::from_cidr("192.168.1.0").is_err());
        assert!(IpAddrMask::from_cidr("192.168.1.0/33").is_err());
        assert!(IpAddrMask::from_cidr("::1/129").is_err());
    }

    #[test]
    fn test_protocol_values() {
        assert_eq!(Protocol::Hopopt.as_u8(), 0);
        assert_eq!(Protocol::Icmp.as_u8(), 1);
        assert_eq!(Protocol::Igmp.as_u8(), 2);
        assert_eq!(Protocol::Tcp.as_u8(), 6);
        assert_eq!(Protocol::Udp.as_u8(), 17);
        assert_eq!(Protocol::Gre.as_u8(), 47);
        assert_eq!(Protocol::Esp.as_u8(), 50);
        assert_eq!(Protocol::Ah.as_u8(), 51);
        assert_eq!(Protocol::Icmpv6.as_u8(), 58);
    }

    #[test]
    fn test_ip_addr_mask_boundary_prefixes_v4() {
        let zero = IpAddrMask::from_cidr("0.0.0.0/0").unwrap();
        assert_eq!(zero.prefix_len, 0);

        let host = IpAddrMask::from_cidr("10.0.0.1/32").unwrap();
        assert_eq!(host.prefix_len, 32);
    }

    #[test]
    fn test_ip_addr_mask_boundary_prefixes_v6() {
        let zero = IpAddrMask::from_cidr("::/0").unwrap();
        assert_eq!(zero.prefix_len, 0);
        assert!(zero.is_ipv6());

        let host = IpAddrMask::from_cidr("::1/128").unwrap();
        assert_eq!(host.prefix_len, 128);
    }

    #[test]
    fn test_ip_addr_mask_equality() {
        let a = IpAddrMask::new("10.0.0.1".parse().unwrap(), 24);
        let b = IpAddrMask::new("10.0.0.1".parse().unwrap(), 24);
        assert_eq!(a, b);

        let c = IpAddrMask::new("10.0.0.1".parse().unwrap(), 16);
        assert_ne!(a, c);
    }

    #[test]
    fn test_ip_addr_mask_multiple_slashes() {
        assert!(IpAddrMask::from_cidr("10.0.0.1/24/8").is_err());
    }

    #[test]
    fn test_ip_addr_mask_empty_string() {
        assert!(IpAddrMask::from_cidr("").is_err());
    }

    #[test]
    fn test_ip_addr_mask_v4_is_not_ipv6() {
        let mask = IpAddrMask::new("192.168.0.1".parse().unwrap(), 24);
        assert!(!mask.is_ipv6());
    }

    #[test]
    fn test_ip_addr_mask_v6_is_ipv6() {
        let mask = IpAddrMask::new("::1".parse().unwrap(), 128);
        assert!(mask.is_ipv6());
    }

    #[test]
    fn test_protocol_copy() {
        let p = Protocol::Tcp;
        let p2 = p; // Copy
        assert_eq!(p, p2);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Icmp.to_string(), "ICMP");
        assert_eq!(Protocol::Icmpv6.to_string(), "ICMPv6");
        assert_eq!(Protocol::Gre.to_string(), "GRE");
        assert_eq!(Protocol::Esp.to_string(), "ESP");
        assert_eq!(Protocol::Ah.to_string(), "AH");
        assert_eq!(Protocol::Igmp.to_string(), "IGMP");
        assert_eq!(Protocol::Hopopt.to_string(), "HOPOPT");
    }
}
