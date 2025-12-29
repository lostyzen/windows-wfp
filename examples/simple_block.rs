//! Simple Block Demo - Add and Remove a WFP Filter
//!
//! This is a minimal example that:
//! 1. Opens a WFP engine session
//! 2. Adds a block filter for notepad.exe
//! 3. Waits 10 seconds (test by launching notepad and trying to access network)
//! 4. Removes the filter
//!
//! # Usage
//!
//! **REQUIRES ADMINISTRATOR PRIVILEGES**
//!
//! ```bash
//! cargo run --example simple_block --release
//! ```

use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use trusty_domain::{Direction, FilterWeight, RuleAction, RuleDef};
use trusty_wfp::{initialize_wfp, FilterBuilder, WfpEngine, WfpResult};

fn main() -> WfpResult<()> {
    println!("🔥 TRusTY Wall - Simple Block Demo\n");

    // Initialize WFP
    println!("📡 Opening WFP Engine...");
    let engine = WfpEngine::new()?;
    println!("✓ Engine opened\n");

    println!("🏗️  Registering provider...");
    initialize_wfp(&engine)?;
    println!("✓ Provider registered\n");

    // Block notepad.exe outbound connections
    println!("🚫 Adding block filter for notepad.exe...");
    let notepad_rule = RuleDef {
        name: "Block Notepad".into(),
        direction: Direction::Outbound,
        action: RuleAction::Block,
        weight: FilterWeight::UserBlock.value(),
        app_path: Some(PathBuf::from(r"C:\Windows\System32\notepad.exe")),
        service_name: None,
        app_container_sid: None,
        local_ip: None,
        remote_ip: None,
        local_port: None,
        remote_port: None,
        protocol: None,
    };

    let filter_id = FilterBuilder::add_filter(&engine, &notepad_rule)?;
    println!("✓ Filter added (ID: {})\n", filter_id);

    println!("⏳ Filter active for 10 seconds...");
    println!("   (Try opening notepad.exe and accessing network)\n");

    for i in (1..=10).rev() {
        println!("   {} seconds remaining...", i);
        thread::sleep(Duration::from_secs(1));
    }

    println!("\n🧹 Removing filter...");
    FilterBuilder::delete_filter(&engine, filter_id)?;
    println!("✓ Filter removed\n");

    println!("✨ Demo complete!");
    Ok(())
}
