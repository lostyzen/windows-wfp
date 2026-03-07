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

use std::thread;
use std::time::Duration;
use windows_wfp::{
    initialize_wfp, Action, Direction, FilterBuilder, FilterRule, FilterWeight, WfpEngine,
    WfpResult,
};

fn main() -> WfpResult<()> {
    println!("TRusTY Wall - Simple Block Demo\n");

    // Initialize WFP
    println!("Opening WFP Engine...");
    let engine = WfpEngine::new()?;
    println!("Engine opened\n");

    println!("Registering provider...");
    initialize_wfp(&engine)?;
    println!("Provider registered\n");

    // Block notepad.exe outbound connections
    println!("Adding block filter for notepad.exe...");
    let notepad_rule = FilterRule::new("Block Notepad", Direction::Outbound, Action::Block)
        .with_weight(FilterWeight::UserBlock)
        .with_app_path(r"C:\Windows\System32\notepad.exe");

    let filter_id = FilterBuilder::add_filter(&engine, &notepad_rule)?;
    println!("Filter added (ID: {})\n", filter_id);

    println!("Filter active for 10 seconds...");
    println!("   (Try opening notepad.exe and accessing network)\n");

    for i in (1..=10).rev() {
        println!("   {} seconds remaining...", i);
        thread::sleep(Duration::from_secs(1));
    }

    println!("\nRemoving filter...");
    FilterBuilder::delete_filter(&engine, filter_id)?;
    println!("Filter removed\n");

    println!("Demo complete!");
    Ok(())
}
