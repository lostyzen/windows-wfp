//! # windows-wfp — Windows Filtering Platform (WFP) Wrapper
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
//! - **Filter Creation** - Builder-pattern filter rules with automatic DOS-to-NT path conversion
//! - **Event Subscription** - Real-time monitoring of network events (learning mode)
//! - **Memory Safety** - All Windows handles managed with RAII, minimal unsafe code
//!
//! ## Quick Start
//!
//! ```no_run
//! use windows_wfp::{WfpEngine, FilterBuilder, FilterRule, Direction, Action, FilterWeight, initialize_wfp};
//!
//! // Open WFP engine (requires Administrator)
//! let engine = WfpEngine::new()?;
//!
//! // Register provider and sublayer
//! initialize_wfp(&engine)?;
//!
//! // Block an application
//! let rule = FilterRule::new("Block curl", Direction::Outbound, Action::Block)
//!     .with_weight(FilterWeight::UserBlock)
//!     .with_app_path(r"C:\Windows\System32\curl.exe");
//!
//! let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
//!
//! // curl.exe is now blocked at kernel level!
//!
//! // Clean up
//! FilterBuilder::delete_filter(&engine, filter_id)?;
//! # Ok::<(), windows_wfp::WfpError>(())
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
//! use windows_wfp::{WfpEngine, WfpEventSubscription};
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
//! # Ok::<(), windows_wfp::WfpError>(())
//! ```

pub mod condition;
pub mod constants;
pub mod engine;
pub mod errors;
pub mod events;
pub mod filter;
pub mod filter_builder;
pub mod layer;
pub mod provider;
pub mod transaction;

// Re-exports
pub use condition::{IpAddrMask, Protocol};
pub use constants::*;
pub use engine::WfpEngine;
pub use errors::{WfpError, WfpResult};
pub use events::{NetworkEvent, NetworkEventType, WfpEventSubscription};
pub use filter::{Action, Direction, FilterRule};
pub use filter_builder::FilterBuilder;
pub use layer::FilterWeight;
pub use provider::{initialize_wfp, WfpProvider, WfpSublayer};
pub use transaction::WfpTransaction;
