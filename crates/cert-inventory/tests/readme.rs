#[path = "common/types.rs"]
mod types;


use cert_inventory::scan::DEFAULT_MAX_FILES;
use cert_inventory::serve::MAX_DEADLINE_SECONDS;
use core_pg::query::{CLIENT_DEADLINE_MARGIN, QUERY_WINDOWS};
use std::fs;
use types::TestResult;


const THOUSAND: u64 = 1_000;


fn readme() -> Result<String, std::io::Error> {
    fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
}


#[test]
fn the_documented_stop_bound_is_built_from_the_code_constants() -> TestResult {
    let margin = CLIENT_DEADLINE_MARGIN.as_secs_f64();
    let bound = format!("paths (at most {DEFAULT_MAX_FILES}) x ({QUERY_WINDOWS} x deadline_seconds + {margin}) + connect_timeout_secs");
    let unit = format!("TimeoutStopSec=<paths x ({QUERY_WINDOWS} x deadline_seconds + {margin}) + connect_timeout_secs + scan time + 30>");
    let text = readme()?;
    assert!(text.contains(&bound), "README lacks: {bound}");
    assert!(text.contains(&unit), "README lacks: {unit}");
    Ok(())
}


#[test]
fn the_documented_deadline_range_is_pinned_to_the_code_maximum() -> TestResult {
    let range = format!(
        "(1 to {} {:03}; the setting is live",
        MAX_DEADLINE_SECONDS / THOUSAND,
        MAX_DEADLINE_SECONDS % THOUSAND
    );
    let text = readme()?;
    assert!(text.contains(&range), "README lacks: {range}");
    assert!(text.contains("size the stop timeout on the largest value ever set"), "live setting");
    assert!(text.contains("synchronous replication and a stalled standby"), "replication");
    Ok(())
}


#[test]
fn the_readme_names_the_scan_and_migration_residuals() -> TestResult {
    let text = readme()?;
    assert!(text.contains("has no deadline of its own"), "scan");
    assert!(
        text.contains("an interrupt during it may still commit after the process has exited"),
        "migration"
    );
    Ok(())
}
