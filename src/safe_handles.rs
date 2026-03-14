//! Safe RAII handle types for WFP resources
//!
//! This module provides zero-cost RAII wrappers for Windows handles used internally
//! by the WFP subsystem. Most users will interact with higher-level types such as
//! [`WfpEngine`](crate::WfpEngine) and [`WfpTransaction`](crate::WfpTransaction) instead.
