# windows-wfp

Safe Rust wrapper for the **Windows Filtering Platform (WFP)** kernel-level firewall API.

[![Crates.io](https://img.shields.io/crates/v/windows-wfp.svg)](https://crates.io/crates/windows-wfp)
[![Documentation](https://docs.rs/windows-wfp/badge.svg)](https://docs.rs/windows-wfp)
[![License: GPL-2.0](https://img.shields.io/crates/l/windows-wfp.svg)](https://opensource.org/licenses/GPL-2.0)

## Overview

WFP is the kernel-level firewall framework in Windows, used by Windows Firewall and third-party security software. This crate provides a high-level, memory-safe Rust interface to create and manage firewall filters without dealing with raw FFI.

### Features

- **WFP Engine** - RAII-based session management with automatic cleanup
- **Provider & Sublayer** - Register custom firewall providers with configurable priority
- **Filter Rules** - Builder-pattern API for creating firewall filters
- **Path Conversion** - Automatic DOS-to-NT kernel path conversion (critical for WFP)
- **Event Monitoring** - Real-time network event subscription
- **Memory Safety** - All Windows handles managed with RAII, minimal unsafe code

## Prerequisites

- **Windows 10/11** (or Windows Server 2016+)
- **Administrator privileges** required at runtime (WFP is a kernel API)
- Rust 1.75+

## Quick Start

```rust,no_run
use windows_wfp::{
    WfpEngine, FilterBuilder, FilterRule, Direction, Action, FilterWeight, initialize_wfp,
};

// Open WFP engine (requires Administrator)
let engine = WfpEngine::new()?;

// Register provider and sublayer
initialize_wfp(&engine)?;

// Block an application
let rule = FilterRule::new("Block curl", Direction::Outbound, Action::Block)
    .with_weight(FilterWeight::UserBlock)
    .with_app_path(r"C:\Windows\System32\curl.exe");

let filter_id = FilterBuilder::add_filter(&engine, &rule)?;

// curl.exe is now blocked at kernel level!

// Clean up
FilterBuilder::delete_filter(&engine, filter_id)?;
# Ok::<(), windows_wfp::WfpError>(())
```

## Filter Conditions

Filters can match on multiple conditions simultaneously:

```rust,no_run
use windows_wfp::*;

let rule = FilterRule::new("HTTPS only", Direction::Outbound, Action::Permit)
    .with_weight(FilterWeight::UserPermit)
    .with_app_path(r"C:\myapp\app.exe")
    .with_protocol(Protocol::Tcp)
    .with_remote_port(443)
    .with_remote_ip(IpAddrMask::from_cidr("0.0.0.0/0").unwrap());
# Ok::<(), windows_wfp::WfpError>(())
```

Available conditions:
- **Application path** - Match by executable (auto-converted to NT kernel path)
- **Protocol** - TCP, UDP, ICMP, ICMPv6, and more
- **Remote/Local port** - Match specific ports
- **Remote/Local IP** - Match IP addresses with CIDR masks (IPv4 and IPv6)
- **Windows service name** - Match by service SID
- **AppContainer SID** - Match UWP/packaged apps

## Path Conversion

WFP operates at the kernel level and requires NT kernel paths, not DOS paths:

| Format | Example |
|--------|---------|
| DOS path (you provide) | `C:\Windows\System32\curl.exe` |
| NT kernel path (WFP needs) | `\device\harddiskvolume4\windows\system32\curl.exe` |

This crate handles the conversion automatically using `FwpmGetAppIdFromFileName0`. Without it, filters would be added successfully but would **never match** any traffic.

## Event Monitoring

Subscribe to real-time network events:

```rust,no_run
use windows_wfp::{WfpEngine, WfpEventSubscription};

let engine = WfpEngine::new()?;
let subscription = WfpEventSubscription::new(&engine)?;

loop {
    match subscription.try_recv() {
        Ok(event) => {
            println!("Event: {:?}", event.event_type);
            println!("App: {:?}", event.app_path);
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(_) => break,
    }
}
# Ok::<(), windows_wfp::WfpError>(())
```

## Examples

Run the included examples (requires Administrator):

```bash
# Block notepad.exe for 10 seconds
cargo run --example simple_block --release

# Block curl.exe and monitor events in real-time
cargo run --example live_demo --release

# List all active WFP filters in the system
cargo run --example list_filters --release
```

## License

Licensed under GPL-2.0. See [LICENSE](LICENSE) for details.
