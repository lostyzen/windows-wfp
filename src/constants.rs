//! WFP GUID constants
//!
//! GUIDs for TRusTY Wall provider, sublayer, and filter layers.

use windows::core::GUID;

/// TRusTY Wall WFP Provider GUID
///
/// Uniquely identifies this firewall application in WFP.
pub const TRUSTY_PROVIDER_GUID: GUID = GUID::from_u128(0x12345678_1234_5678_1234_567812345678);

/// TRusTY Wall WFP Sublayer GUID
///
/// All TRusTY Wall filters are added to this sublayer.
pub const TRUSTY_SUBLAYER_GUID: GUID = GUID::from_u128(0x87654321_4321_8765_4321_876543218765);

/// WFP Layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4
///
/// Application Layer Enforcement (ALE) for IPv4 outbound connections.
pub const LAYER_ALE_AUTH_CONNECT_V4: GUID = GUID::from_u128(0xc38d57d1_05a7_4c33_904f_7fbceee60e82);

/// WFP Layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6
///
/// Application Layer Enforcement (ALE) for IPv6 outbound connections.
pub const LAYER_ALE_AUTH_CONNECT_V6: GUID = GUID::from_u128(0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4);

/// WFP Layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
///
/// Application Layer Enforcement (ALE) for IPv4 inbound connections.
pub const LAYER_ALE_AUTH_RECV_ACCEPT_V4: GUID = GUID::from_u128(0xe1cd9fe7_f4b5_4273_96c0_592695c5f7b8);

/// WFP Layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
///
/// Application Layer Enforcement (ALE) for IPv6 inbound connections.
pub const LAYER_ALE_AUTH_RECV_ACCEPT_V6: GUID = GUID::from_u128(0xa3b42c97_9f04_4672_b87e_cee9c483257f);

/// WFP Condition: FWPM_CONDITION_ALE_APP_ID
///
/// Filter condition for application path.
pub const CONDITION_ALE_APP_ID: GUID = GUID::from_u128(0xd78e1e87_8644_4ea5_9437_d809ecefc971);

/// WFP Condition: FWPM_CONDITION_IP_REMOTE_ADDRESS
///
/// Filter condition for remote IP address.
pub const CONDITION_IP_REMOTE_ADDRESS: GUID = GUID::from_u128(0xb235ae9a_1d64_49b8_a44c_5ff3d9095045);

/// WFP Condition: FWPM_CONDITION_IP_REMOTE_PORT
///
/// Filter condition for remote port.
pub const CONDITION_IP_REMOTE_PORT: GUID = GUID::from_u128(0xc35a604d_d22b_4e1a_91b4_68f674ee674b);

/// WFP Condition: FWPM_CONDITION_IP_LOCAL_PORT
///
/// Filter condition for local port.
pub const CONDITION_IP_LOCAL_PORT: GUID = GUID::from_u128(0x0c1ba1af_5765_453f_af22_a8f791ac775b);

/// WFP Condition: FWPM_CONDITION_IP_PROTOCOL
///
/// Filter condition for IP protocol (TCP, UDP, ICMP).
pub const CONDITION_IP_PROTOCOL: GUID = GUID::from_u128(0x3971ef2b_623e_4f9a_8cb1_6e79b806b9a7);
