//! The longest a stop can wait for the round in flight, from the settings and the constants of the code that runs it; `README.md` states the same formula.

use crate::cmdb_sync::PAGE_OBSERVATIONS;
use crate::settings::FetchSettings;
use cmdb::model::Limits;
use cmdb::store::ATTEMPT_CEILING;
use core_pg::query::{CLIENT_DEADLINE_MARGIN, QUERY_WINDOWS};
use core_pg::settings::PgSettings;


pub const MILLIS_PER_SECOND: u64 = 1000;


pub const APPLY_STATEMENTS: u64 = 1;


pub const APPLY_RUNS_PER_PAGE: u64 = 2;


pub const TABLES_READ: u64 = 3;


/// What the client waits for one statement: `QUERY_WINDOWS` server windows plus the margin.
pub fn statement_cut_secs(statement_timeout_secs: u64) -> u64 {
    statement_timeout_secs
        .saturating_mul(u64::from(QUERY_WINDOWS))
        .saturating_add(CLIENT_DEADLINE_MARGIN.as_secs())
}


/// Keyset statements of one table read of at most `max_rows` rows.
pub fn statements_of_read(max_rows: usize, page_size: usize) -> u64 {
    (max_rows / page_size.max(1) + 1) as u64
}


/// The three table reads of `load_assets` plus the one apply.
pub fn statements_per_attempt(limits: &Limits) -> u64 {
    statements_of_read(limits.max_assets, limits.page_size)
        .saturating_add(statements_of_read(limits.max_child_rows, limits.page_size).saturating_mul(TABLES_READ - 1))
        .saturating_add(APPLY_STATEMENTS)
}


/// `apply_page` runs `apply_attempts` twice when the store refuses for a cap, each at most `max_attempts` times (and `ATTEMPT_CEILING`).
pub fn attempts_per_page(limits: &Limits) -> u64 {
    (limits.max_attempts.min(ATTEMPT_CEILING) as u64).saturating_mul(APPLY_RUNS_PER_PAGE)
}


pub fn pages_of(fetch: &FetchSettings) -> u64 {
    fetch.limits.max_items.div_ceil(PAGE_OBSERVATIONS) as u64
}


pub fn fetch_secs(fetch: &FetchSettings) -> u64 {
    fetch.timeout_ms.div_ceil(MILLIS_PER_SECOND)
}


/// The sync phase alone: pages x attempts x statements x the cut of one statement.
pub fn sync_secs(fetch: &FetchSettings, pg: &PgSettings, limits: &Limits) -> u64 {
    pages_of(fetch)
        .saturating_mul(attempts_per_page(limits))
        .saturating_mul(statements_per_attempt(limits))
        .saturating_mul(statement_cut_secs(pg.statement_timeout_secs))
}


/// Fetch deadline, then the connect deadline, then the sync phase.
pub fn stop_bound_secs(fetch: &FetchSettings, pg: &PgSettings, limits: &Limits) -> u64 {
    fetch_secs(fetch)
        .saturating_add(pg.connect_timeout_secs)
        .saturating_add(sync_secs(fetch, pg, limits))
}
