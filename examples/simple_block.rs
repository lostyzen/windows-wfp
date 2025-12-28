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
use trusty_wfp::{WfpEngine, FilterBuilder, WfpResult, initialize_wfp};
use trusty_domain::{RuleDef, Direction, RuleAction, FilterWeight};

fn main() -> WfpResult<()> {
    println!("🔥 TRusTY Wall - Simple Block Demo\n");

    // Initialize WFP
    println!("📡 Opening WFP Engine...");
    let engine = WfpEngine::new("TRusTY Wall Simple", "Simple block test", 5000)?;
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

    let mut filter_builder = FilterBuilder::new(&engine);
    let filter_id = filter_builder.add_filter(&notepad_rule)?;
    println!("✓ Filter added (ID: {})\n", filter_id);

    println!("⏳ Filter active for 10 seconds...");
    println!("   (Try opening notepad.exe and accessing network)\n");

    for i in (1..=10).rev() {
        println!("   {} seconds remaining...", i);
        thread::sleep(Duration::from_secs(1));
    }

    println!("\n🧹 Removing filter...");
    filter_builder.delete_filter(filter_id)?;
    println!("✓ Filter removed\n");

    println!("✨ Demo complete!");
    Ok(())
}
