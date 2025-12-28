//! # TRusTY Wall - Windows Filtering Platform (WFP) Wrapper
//!
//! Safe Rust wrapper around Windows Filtering Platform APIs.
//!
//! This crate provides a high-level, memory-safe interface to the Windows Filtering Platform (WFP),
//! the kernel-level firewall API in Windows. It handles all the complex FFI interactions, memory
//! management, and path conversions required for WFP to work correctly.
//!
//! ## Features
//!
//! - **WFP Engine Management** - RAII-based session lifecycle with automatic cleanup
//! - **Provider & Sublayer** - Registration of custom firewall provider with high priority
//! - **Filter Creation** - Translate domain rules to WFP filters with automatic DOS-to-NT path conversion
//! - **Event Subscription** - Real-time monitoring of network events (learning mode)
//! - **Memory Safety** - All Windows handles managed with RAII, minimal unsafe code
//!
//! ## Quick Start
//!
//! ```no_run
//! use trusty_wfp::{WfpEngine, FilterBuilder, initialize_wfp};
//! use trusty_domain::{RuleDef, Direction, RuleAction, FilterWeight};
//! use std::path::PathBuf;
//!
//! // Open WFP engine (requires Administrator)
//! let engine = WfpEngine::new()?;
//!
//! // Register provider and sublayer
//! initialize_wfp(&engine)?;
//!
//! // Block an application
//! let rule = RuleDef {
//!     name: "Block curl".into(),
//!     direction: Direction::Outbound,
//!     action: RuleAction::Block,
//!     weight: FilterWeight::UserBlock.value(),
//!     app_path: Some(PathBuf::from(r"C:\Windows\System32\curl.exe")),
//!     // ... other fields
//!     # service_name: None,
//!     # app_container_sid: None,
//!     # local_ip: None,
//!     # remote_ip: None,
//!     # local_port: None,
//!     # remote_port: None,
//!     # protocol: None,
//! };
//!
//! let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
//!
//! // curl.exe is now blocked at kernel level!
//!
//! // Clean up
//! FilterBuilder::delete_filter(&engine, filter_id)?;
//! # Ok::<(), trusty_wfp::WfpError>(())
//! ```
//!
//! ## Path Conversion
//!
//! **CRITICAL**: WFP operates at the Windows kernel level and requires NT kernel paths.
//! This crate automatically converts DOS paths to NT kernel format:
//!
//! - **DOS path**: `C:\Windows\System32\curl.exe` (what you provide)
//! - **NT kernel path**: `\device\harddiskvolume4\windows\system32\curl.exe` (what WFP needs)
//!
//! Without this conversion, filters would be added successfully but would **never match**
//! any traffic. This crate handles the conversion automatically using `FwpmGetAppIdFromFileName0`.
//!
//! ## Event Monitoring
//!
//! Subscribe to network events for learning mode:
//!
//! ```no_run
//! use trusty_wfp::{WfpEngine, WfpEventSubscription};
//!
//! let engine = WfpEngine::new()?;
//! let subscription = WfpEventSubscription::new(&engine)?;
//!
//! loop {
//!     match subscription.try_recv() {
//!         Ok(event) => {
//!             println!("Event: {:?}", event.event_type);
//!             println!("App: {:?}", event.app_path);
//!         }
//!         Err(std::sync::mpsc::TryRecvError::Empty) => {
//!             std::thread::sleep(std::time::Duration::from_millis(100));
//!         }
//!         Err(_) => break,
//!     }
//! }
//! # Ok::<(), trusty_wfp::WfpError>(())
//! ```
//!
//! ## Examples
//!
//! See the `examples/` directory for complete demonstrations:
//!
//! - `simple_block.rs` - Basic filter addition and removal
//! - `live_demo.rs` - Full demo with event monitoring
//! - `list_filters.rs` - Enumerate all WFP filters in the system
//!
//! Run examples (requires Administrator):
//! ```bash
//! cargo run --example live_demo --release
//! ```
//!
//! ## Architecture
//!
//! This crate is part of the TRusTY Wall firewall project and sits at the infrastructure layer,
//! providing the adapter between domain rules ([`RuleDef`](trusty_domain::RuleDef)) and the
//! Windows kernel-level firewall.
//!
//! ## Safety
//!
//! WFP requires FFI calls to Windows APIs. This crate minimizes unsafe code:
//! - All Windows handles use RAII (`Drop` trait) for automatic cleanup
//! - FFI boundaries are well-isolated in specific modules
//! - Memory allocated by WFP is properly freed with `FwpmFreeMemory0`
//! - Wide string conversions are handled safely

pub mod constants;
pub mod engine;
pub mod filter;
pub mod transaction;
pub mod layer;
pub mod condition;
pub mod safe_handles;
pub mod errors;
pub mod provider;
pub mod filter_builder;
pub mod events;

// Re-exports
pub use engine::WfpEngine;
pub use transaction::WfpTransaction;
pub use provider::{WfpProvider, WfpSublayer, initialize_wfp};
pub use filter_builder::FilterBuilder;
pub use events::{NetworkEvent, NetworkEventType, WfpEventSubscription};
// pub use filter::Filter;
pub use errors::{WfpError, WfpResult};
pub use constants::*;
