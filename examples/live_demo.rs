//! Live WFP Demo - Block Application & Monitor Events
//!
//! This example demonstrates the complete WFP implementation:
//! 1. Initialize WFP provider/sublayer
//! 2. Block a specific application (curl.exe)
//! 3. Subscribe to network events
//! 4. Monitor blocked connections in real-time
//!
//! # Usage
//!
//! **REQUIRES ADMINISTRATOR PRIVILEGES**
//!
//! ```bash
//! cargo run --example live_demo --release
//! ```
//!
//! Then in another terminal, try:
//! ```bash
//! curl https://google.com
//! ```
//!
//! You should see the connection blocked and logged!

use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use trusty_domain::{Direction, FilterWeight, RuleAction, RuleDef};
use trusty_wfp::{
    initialize_wfp, FilterBuilder, NetworkEvent, WfpEngine, WfpEventSubscription, WfpResult,
};

fn main() -> WfpResult<()> {
    println!("🔥 TRusTY Wall - Live WFP Demo");
    println!("================================\n");

    // Check for admin privileges
    if !is_elevated() {
        eprintln!("❌ ERROR: This demo requires Administrator privileges!");
        eprintln!("   Please run: cargo run --example live_demo --release");
        eprintln!("   from an Administrator command prompt.\n");
        std::process::exit(1);
    }

    println!("✅ Running with Administrator privileges\n");

    // Step 1: Initialize WFP Engine
    println!("📡 Step 1: Opening WFP Engine session...");
    let engine = WfpEngine::new()?;
    println!("   ✓ Engine session opened\n");

    // Step 2: Register Provider & Sublayer
    println!("🏗️  Step 2: Registering WFP provider & sublayer...");
    initialize_wfp(&engine)?;
    println!("   ✓ Provider & sublayer registered\n");

    // Step 3: Subscribe to network events
    println!("📻 Step 3: Subscribing to network events...");
    let event_subscription = WfpEventSubscription::new(&engine)?;
    println!("   ✓ Event subscription active\n");

    // Step 4: Add blocking filter for curl.exe
    println!("🚫 Step 4: Adding block filter for curl.exe...");
    let curl_path = find_curl_path();
    println!("   Target: {}", curl_path.display());

    let block_rule = RuleDef {
        name: "Block curl.exe".into(),
        direction: Direction::Outbound,
        action: RuleAction::Block,
        weight: FilterWeight::UserBlock.value(),
        app_path: Some(curl_path.clone()),
        service_name: None,
        app_container_sid: None,
        local_ip: None,
        remote_ip: None,
        local_port: None,
        remote_port: None,
        protocol: None,
    };

    let filter_id = FilterBuilder::add_filter(&engine, &block_rule)?;
    println!("   ✓ Filter added (ID: {})\n", filter_id);

    // Step 5: Monitor events
    println!("👀 Step 5: Monitoring network events...");
    println!("   Press Ctrl+C to stop\n");
    println!("💡 TIP: In another terminal, run:");
    println!("   > curl https://google.com");
    println!("   You should see the connection BLOCKED below!\n");
    println!("═══════════════════════════════════════════════════════\n");

    let start_time = std::time::Instant::now();
    let mut event_count = 0;

    loop {
        // Non-blocking check for events
        match event_subscription.try_recv() {
            Ok(event) => {
                event_count += 1;
                print_event(&event, event_count);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                // No events, sleep briefly
                thread::sleep(Duration::from_millis(100));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                println!("\n❌ Event channel disconnected!");
                break;
            }
        }

        // Auto-stop after 60 seconds for demo
        if start_time.elapsed() > Duration::from_secs(60) {
            println!("\n⏰ Demo timeout (60s) - stopping...");
            break;
        }
    }

    // Cleanup
    println!("\n🧹 Cleaning up...");
    FilterBuilder::delete_filter(&engine, filter_id)?;
    println!("   ✓ Filter removed");
    drop(event_subscription);
    println!("   ✓ Event subscription closed");
    drop(engine);
    println!("   ✓ Engine session closed\n");

    println!("✨ Demo complete! {} events captured.", event_count);
    Ok(())
}

fn print_event(event: &NetworkEvent, count: usize) {
    println!("🔔 Event #{}: {:?}", count, event.event_type);
    println!("   Timestamp:   {:?}", event.timestamp);

    if let Some(ref path) = event.app_path {
        println!("   Application: {}", path.display());
    }

    if let Some(local) = event.local_addr {
        println!("   Local:       {}:{}", local, event.local_port);
    }

    if let Some(remote) = event.remote_addr {
        println!("   Remote:      {}:{}", remote, event.remote_port);
    }

    println!("   Protocol:    {}", event.protocol);

    if let Some(filter_id) = event.filter_id {
        println!("   Filter ID:   {}", filter_id);
    }

    if let Some(layer_id) = event.layer_id {
        println!("   Layer ID:    {}", layer_id);
    }

    println!();
}

fn find_curl_path() -> PathBuf {
    // Common curl.exe locations
    let candidates = vec![
        r"C:\Windows\System32\curl.exe",
        r"C:\Program Files\Git\mingw64\bin\curl.exe",
        r"C:\tools\curl\bin\curl.exe",
    ];

    for path in candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    // Default to System32 location (most common on Windows 10/11)
    PathBuf::from(r"C:\Windows\System32\curl.exe")
}

fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use std::mem;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = HANDLE::default();
            let process = GetCurrentProcess();

            if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned_length: u32 = 0;

            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned_length,
            );

            let _ = CloseHandle(token);

            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(not(windows))]
    false
}
