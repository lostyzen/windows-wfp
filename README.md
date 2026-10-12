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

let filter = FilterBuilder::add_filter(&engine, &rule)?;

// curl.exe is now blocked at kernel level, over IPv4 and IPv6!

// Clean up
FilterBuilder::delete_filter(&engine, &filter)?;
# Ok::<(), windows_wfp::WfpError>(())
```

A rule without IP-address conditions is installed on both the IPv4 and IPv6 layers;
`add_filter` returns a `FilterHandle` owning all the created filter IDs.

## Provider Identity

All filters belong to a WFP provider and sublayer. Use your own GUIDs so your filters
do not collide with other applications using this crate:

```rust,no_run
use windows_wfp::{initialize_wfp, WfpConfig, WfpEngine};
use windows::core::GUID;

let engine = WfpEngine::new()?.with_config(WfpConfig {
    provider_key: GUID::from_u128(0x0b9a3c1e_5d2f_4e6a_9b7c_1d2e3f4a5b6c),
    sublayer_key: GUID::from_u128(0x7c6b5a4f_3e2d_4c1b_8a9f_0e1d2c3b4a59),
    display_name: "my-firewall".into(),
    ..WfpConfig::default()
});
initialize_wfp(&engine)?;
# Ok::<(), windows_wfp::WfpError>(())
```

With the default dynamic session, the provider, sublayer and filters are removed
when the `WfpEngine` is dropped.

## Filter Conditions

Filters can match on multiple conditions simultaneously:

```rust,no_run
use windows_wfp::*;

let rule = FilterRule::new("HTTPS only", Direction::Outbound, Action::Permit)
    .with_weight(FilterWeight::UserPermit)
    .with_app_path(r"C:\myapp\app.exe")
    .with_protocol(Protocol::Tcp)
    .with_remote_port(443);
// No IP condition: installed on both the IPv4 and IPv6 layers.

// An IP condition pins the rule to that address family:
let ipv4_only = rule.clone().with_remote_ip(IpAddrMask::from_cidr("0.0.0.0/0")?); // all IPv4, no IPv6
let lan_only = rule.with_remote_ip(IpAddrMask::from_cidr("192.168.0.0/16")?);      // IPv4 LAN only
# Ok::<(), windows_wfp::WfpError>(())
```

Available conditions:
- **Application path** - Match by executable (auto-converted to NT kernel path)
- **Protocol** - TCP, UDP, ICMP, ICMPv6, and more
- **Remote/Local port** - Match specific ports
- **Remote/Local IP** - Match IP addresses with CIDR masks (IPv4 and IPv6)

Not supported yet (rules using them are rejected with `WfpError::UnsupportedCondition`
instead of silently matching all traffic):
- **Windows service name**
- **AppContainer SID**

## Rule Validation

`FilterRule::new(name, direction, action)` is all a rule needs; every condition is optional
and a rule without conditions matches all traffic in that direction. Before calling WFP,
`FilterBuilder::add_filter` checks the rule, in this order:

| Check | Error |
|---|---|
| No unsupported condition (`service_name`, `app_container_sid`) | `WfpError::UnsupportedCondition` |
| CIDR prefix within range (≤ /32 for IPv4, ≤ /128 for IPv6) | `WfpError::InvalidAddress` |
| Remote IP, local IP and ICMP/ICMPv6 protocol all target the same IP family | `WfpError::InvalidRule` |
| `app_path` points to an existing executable | `WfpError::AppPathNotFound` |

A rejected rule installs nothing. Once these checks pass, the remaining failures come from
WFP itself (`WfpError::Api`), e.g. missing Administrator rights or `initialize_wfp` not called.

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
use windows_wfp::WfpEventSubscription;

// Uses its own WFP session: can be moved to another thread freely
let subscription = WfpEventSubscription::new()?;

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

Event fields (`app_path`, addresses, ports, protocol) are `None` when WFP did not
provide them. `app_path` is in NT kernel format (`\device\harddiskvolume3\...`).

Windows does not collect `ClassifyAllow` events by default. Enable them with
`engine.set_classify_allow_events(true)`; note this is a **system-wide, persistent**
setting.

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
