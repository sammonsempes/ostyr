#[path = "common/types.rs"]
mod types;


use cmdb::model::{DEFAULT_MAX_ASSETS, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_CHILD_ROWS, DEFAULT_PAGE_SIZE};
use core_pg::query::{CLIENT_DEADLINE_MARGIN, QUERY_WINDOWS};
use core_pg::settings::{DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_STATEMENT_TIMEOUT_SECS, MAX_DEADLINE_SECS};
use k8s_inventory::cmdb_sync::{APPLY_RUNS_PER_PAGE, PAGE_OBSERVATIONS};
use k8s_inventory::limits::{CEILING_TOTAL_ITEMS, DEFAULT_MAX_TOTAL_ITEMS};
use k8s_inventory::settings::{DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS};
use std::fs;
use types::TestResult;


const LISTS: u64 = 2;


const CHILD_TABLES: u64 = 2;


const MILLIS: u64 = 1_000;


fn deploy() -> Result<String, std::io::Error> {
    fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/DEPLOY.md"))
}


fn statements_per_attempt() -> u64 {
    let page = DEFAULT_PAGE_SIZE as u64;
    (DEFAULT_MAX_ASSETS as u64 / page + 1) + CHILD_TABLES * (DEFAULT_MAX_CHILD_ROWS as u64 / page + 1) + 1
}


fn pages(total_items: usize) -> u64 {
    (LISTS * total_items as u64).div_ceil(PAGE_OBSERVATIONS as u64)
}


fn bound(timeout_ms: u64, connect_secs: u64, total_items: usize, statement_secs: u64) -> u64 {
    let statement_cut = u64::from(QUERY_WINDOWS) * statement_secs + CLIENT_DEADLINE_MARGIN.as_secs();
    let runs = APPLY_RUNS_PER_PAGE as u64 * DEFAULT_MAX_ATTEMPTS as u64;
    timeout_ms / MILLIS + connect_secs + pages(total_items) * runs * statements_per_attempt() * statement_cut
}


#[test]
fn the_documented_stop_bound_is_built_from_the_code_constants() -> TestResult {
    let text = deploy()?;
    let margin = CLIENT_DEADLINE_MARGIN.as_secs();
    let formula = format!(
        "TimeoutStopSec >= timeout_ms / 1000 + connect_timeout_secs + pages x {APPLY_RUNS_PER_PAGE} x max_attempts x statements x ({QUERY_WINDOWS} x statement_timeout_secs + {margin})"
    );
    let pages_line = format!("pages = {LISTS} x max_total_items / {PAGE_OBSERVATIONS}, rounded up");
    let statements_line = format!(
        "statements = (max_assets / page_size + 1) + {CHILD_TABLES} x (max_child_rows / page_size + 1) + 1, with page_size {DEFAULT_PAGE_SIZE}"
    );
    let defaults = bound(
        DEFAULT_TIMEOUT_MS,
        DEFAULT_CONNECT_TIMEOUT_SECS,
        DEFAULT_MAX_TOTAL_ITEMS,
        DEFAULT_STATEMENT_TIMEOUT_SECS,
    );
    let ceilings = bound(MAX_TIMEOUT_MS, MAX_DEADLINE_SECS, CEILING_TOTAL_ITEMS, MAX_DEADLINE_SECS);
    let default_line = format!(
        "At the defaults ({} pages, max_attempts {DEFAULT_MAX_ATTEMPTS}, {} statements, {DEFAULT_STATEMENT_TIMEOUT_SECS} s) the bound is {defaults} s.",
        pages(DEFAULT_MAX_TOTAL_ITEMS),
        statements_per_attempt()
    );
    let ceiling_line = format!(
        "At the ceilings ({} pages, statement_timeout_secs {MAX_DEADLINE_SECS}) the bound is {ceilings} s.",
        pages(CEILING_TOTAL_ITEMS)
    );
    [formula, pages_line, statements_line, default_line, ceiling_line]
        .iter()
        .for_each(|line| assert!(text.contains(line), "DEPLOY.md lacks: {line}"));
    Ok(())
}


#[test]
fn the_bound_past_an_hour_advises_no_stop_timeout_and_names_the_residual() -> TestResult {
    let text = deploy()?;
    assert!(text.contains("TimeoutStopSec=infinity"));
    assert!(text.contains("Residual:"));
    Ok(())
}
