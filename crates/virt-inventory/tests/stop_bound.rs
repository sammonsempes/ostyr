#[path = "common/types.rs"]
mod types;


use cmdb::model::{Limits, DEFAULT_MAX_ASSETS, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_CHILD_ROWS, DEFAULT_PAGE_SIZE};
use cmdb::store::ATTEMPT_CEILING;
use core_pg::query::{CLIENT_DEADLINE_MARGIN, QUERY_WINDOWS};
use core_pg::settings::{PgSettings, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_STATEMENT_TIMEOUT_SECS};
use std::path::PathBuf;
use types::TestResult;
use virt_inventory::cmdb_sync::PAGE_OBSERVATIONS;
use virt_inventory::limits::{Limits as FetchLimits, DEFAULT_MAX_ITEMS};
use virt_inventory::settings::FetchSettings;
use virt_inventory::stop_bound::{
    attempts_per_page, pages_of, statement_cut_secs, statements_of_read, statements_per_attempt, stop_bound_secs, sync_secs,
};


const README: &str = include_str!("../README.md");


const FETCH_TIMEOUT_MS: u64 = 30_000;


const LAB_ITEMS: usize = 100;


const LAB_CAP: usize = 500;


const LAB_STATEMENT_TIMEOUT: u64 = 10;


const SPLIT_TIMEOUT_MS: u64 = 1500;


const DATABASE_PORT: u16 = 5432;


fn fetch_with(max_items: usize, timeout_ms: u64) -> FetchSettings {
    FetchSettings {
        api_url: "https://pve:8006".to_owned(),
        ca_file: PathBuf::from("/ca"),
        token_file: PathBuf::from("/token"),
        tenant: "acme".to_owned(),
        cluster: "pve-1".to_owned(),
        timeout_ms,
        limits: FetchLimits {
            max_items,
            ..FetchLimits::default()
        },
    }
}


fn pg_with(statement_timeout_secs: u64, connect_timeout_secs: u64) -> PgSettings {
    PgSettings {
        host: "db".to_owned(),
        port: DATABASE_PORT,
        database: "ostyr".to_owned(),
        user: "ostyr".to_owned(),
        password_file: "/p".to_owned(),
        ca_file: "/c".to_owned(),
        connect_timeout_secs,
        statement_timeout_secs,
    }
}


fn documented(name: &str) -> Option<u64> {
    README
        .lines()
        .find_map(|line| line.strip_prefix(&format!("- `{name} = "))?.strip_suffix('`')?.parse().ok())
}


#[test]
fn every_constant_and_worked_figure_in_the_readme_equals_the_code() -> TestResult {
    let lab = Limits {
        max_assets: LAB_CAP,
        max_child_rows: LAB_CAP,
        ..Limits::default()
    };
    let lab_bound = stop_bound_secs(
        &fetch_with(LAB_ITEMS, FETCH_TIMEOUT_MS),
        &pg_with(LAB_STATEMENT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT_SECS),
        &lab,
    );
    let default_bound = stop_bound_secs(
        &fetch_with(DEFAULT_MAX_ITEMS, FETCH_TIMEOUT_MS),
        &pg_with(DEFAULT_STATEMENT_TIMEOUT_SECS, DEFAULT_CONNECT_TIMEOUT_SECS),
        &Limits::default(),
    );
    let facts = [
        ("QUERY_WINDOWS", u64::from(QUERY_WINDOWS)),
        ("CLIENT_DEADLINE_MARGIN_SECS", CLIENT_DEADLINE_MARGIN.as_secs()),
        ("PAGE_OBSERVATIONS", PAGE_OBSERVATIONS as u64),
        ("ATTEMPT_CEILING", ATTEMPT_CEILING as u64),
        ("DEFAULT_PAGE_SIZE", DEFAULT_PAGE_SIZE as u64),
        ("DEFAULT_MAX_ASSETS", DEFAULT_MAX_ASSETS as u64),
        ("DEFAULT_MAX_CHILD_ROWS", DEFAULT_MAX_CHILD_ROWS as u64),
        ("DEFAULT_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS as u64),
        ("DEFAULT_MAX_ITEMS", DEFAULT_MAX_ITEMS as u64),
        ("DEFAULT_STATEMENT_TIMEOUT_SECS", DEFAULT_STATEMENT_TIMEOUT_SECS),
        ("DEFAULT_CONNECT_TIMEOUT_SECS", DEFAULT_CONNECT_TIMEOUT_SECS),
        ("WORKED_LAB_SECS", lab_bound),
        ("WORKED_DEFAULT_SECS", default_bound),
    ];
    facts
        .iter()
        .for_each(|(name, value)| assert_eq!(documented(name), Some(*value), "README.md line for {name}"));
    Ok(())
}


const LAB_CUT: u64 = 25;


const LAB_READS: u64 = 2;


const DEFAULT_STATEMENTS: u64 = 824;


const DEFAULT_ATTEMPTS: u64 = 6;


const ONE_TABLE_PAGES: u64 = 2;


const EXTRA_ATTEMPTS: usize = 5;


const CEILING_ATTEMPTS: u64 = 20;


const TWO_PAGES: u64 = 2;


const SPLIT_CONNECT: u64 = 7;


const SPLIT_FETCH_SECONDS: u64 = 2;


const SHORT_STATEMENT: u64 = 1;


const SHORT_CUT: u64 = 7;


#[test]
fn the_parts_of_the_formula_follow_the_settings() -> TestResult {
    let limits = Limits::default();
    assert_eq!(statement_cut_secs(LAB_STATEMENT_TIMEOUT), LAB_CUT);
    assert_eq!(statements_of_read(LAB_CAP, LAB_CAP), LAB_READS);
    assert_eq!(statements_of_read(1, 0), LAB_READS);
    assert_eq!(statements_per_attempt(&limits), DEFAULT_STATEMENTS);
    assert_eq!(attempts_per_page(&limits), DEFAULT_ATTEMPTS);
    let above_ceiling = Limits {
        max_attempts: ATTEMPT_CEILING + EXTRA_ATTEMPTS,
        ..limits
    };
    assert_eq!(attempts_per_page(&above_ceiling), CEILING_ATTEMPTS);
    assert_eq!(pages_of(&fetch_with(LAB_ITEMS + 1, FETCH_TIMEOUT_MS)), ONE_TABLE_PAGES);
    assert_eq!(pages_of(&fetch_with(0, FETCH_TIMEOUT_MS)), 0);
    let split = stop_bound_secs(&fetch_with(0, SPLIT_TIMEOUT_MS), &pg_with(SHORT_STATEMENT, SPLIT_CONNECT), &limits);
    assert_eq!(
        split,
        SPLIT_FETCH_SECONDS + SPLIT_CONNECT,
        "the fetch deadline rounds up, no page means no sync phase"
    );
    let short = sync_secs(&fetch_with(LAB_ITEMS, FETCH_TIMEOUT_MS), &pg_with(SHORT_STATEMENT, 1), &limits);
    assert_eq!(short, DEFAULT_ATTEMPTS * DEFAULT_STATEMENTS * SHORT_CUT);
    assert_eq!(TWO_PAGES, ONE_TABLE_PAGES);
    Ok(())
}
