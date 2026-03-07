//! List all WFP filters
//!
//! This example enumerates and displays all active WFP filters in the system.
//! Useful for debugging and seeing what firewalls are doing.
//!
//! # Usage
//!
//! **REQUIRES ADMINISTRATOR PRIVILEGES**
//!
//! ```bash
//! cargo run --example list_filters --release
//! ```

use windows_wfp::{FilterAction, FilterEnumerator, WfpEngine, WfpResult};

fn main() -> WfpResult<()> {
    println!("WFP Filter Enumeration\n");

    let engine = WfpEngine::new()?;
    let filters = FilterEnumerator::all(&engine)?;

    println!(
        "{:<10} {:<40} {:<15} {:<15} {:<60}",
        "Filter ID", "Name", "Action", "Weight", "App Path"
    );
    println!("{:-<140}", "");

    for filter in &filters {
        let action = match filter.action {
            FilterAction::Block => "BLOCK",
            FilterAction::Permit => "PERMIT",
            FilterAction::CalloutTerminating => "CALLOUT_TERM",
            FilterAction::CalloutInspection => "CALLOUT_INSP",
            FilterAction::CalloutUnknown => "CALLOUT_UNK",
            FilterAction::Other(_) => "OTHER",
        };

        let name: String = if filter.name.chars().count() > 40 {
            let truncated: String = filter.name.chars().take(37).collect();
            format!("{}...", truncated)
        } else {
            filter.name.clone()
        };

        let app = filter
            .app_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        println!(
            "{:<10} {:<40} {:<15} {:<15} {:<60}",
            filter.id, name, action, filter.weight, app
        );
    }

    println!("{:-<140}", "");
    println!("\nTotal filters: {}", filters.len());

    Ok(())
}
