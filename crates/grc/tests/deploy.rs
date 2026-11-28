use core_pg::migrate::{MIGRATION_CLIENT_MARGIN, MIGRATION_DEADLINE};
use core_pg::query::CLIENT_DEADLINE_MARGIN;
use core_pg::settings::{default_connect_timeout, default_statement_timeout};
use grc::service::MAX_FRAMEWORKS;


#[path = "common/types.rs"]
mod types;


use types::TestResult;


const DEPLOY: &str = include_str!("../DEPLOY.md");


const STATEMENTS_PER_FRAMEWORK: u64 = 3;


const QUERY_FACTOR: u64 = 2;


const MIGRATION_WAITS: u64 = 3;


const MIGRATION_READS: u64 = 5;


const GROUP: usize = 3;


const LOWERED_STATEMENT_SECONDS: u64 = 10;


pub fn grouped(number: u64) -> String {
    let text = number.to_string();
    let length = text.len();
    text.chars()
        .enumerate()
        .map(|(index, symbol)| {
            if index > 0 && (length - index).is_multiple_of(GROUP) {
                format!(" {symbol}")
            } else {
                symbol.to_string()
            }
        })
        .collect()
}


pub fn round_bound(connect: u64, statement: u64) -> u64 {
    connect + MAX_FRAMEWORKS as u64 * STATEMENTS_PER_FRAMEWORK * QUERY_FACTOR * (statement + CLIENT_DEADLINE_MARGIN.as_secs())
}


pub fn start_bound(connect: u64, statement: u64) -> u64 {
    connect
        + MIGRATION_WAITS * (MIGRATION_DEADLINE.as_secs() + MIGRATION_CLIENT_MARGIN.as_secs())
        + MIGRATION_READS * QUERY_FACTOR * (statement + CLIENT_DEADLINE_MARGIN.as_secs())
        + round_bound(connect, statement)
}


#[test]
fn the_documented_stop_bounds_are_the_ones_the_constants_give() -> TestResult {
    let connect = default_connect_timeout();
    let statement = default_statement_timeout();
    assert!(
        DEPLOY.contains(&format!("this is {} seconds", grouped(round_bound(connect, statement)))),
        "round bound"
    );
    assert!(
        DEPLOY.contains(&format!("this is {} seconds", grouped(start_bound(connect, statement)))),
        "start bound"
    );
    assert!(
        DEPLOY.contains(&format!(
            "gives a round bound of {} seconds",
            grouped(round_bound(connect, LOWERED_STATEMENT_SECONDS))
        )),
        "lowered bound"
    );
    assert!(DEPLOY.contains(&format!(
        "at most {} seconds plus a {} second margin",
        grouped(MIGRATION_DEADLINE.as_secs()),
        MIGRATION_CLIENT_MARGIN.as_secs()
    )));
    assert!(DEPLOY.contains("start bound = connect_timeout_secs + 3 x (3 600 + 5) + 5 x 2 x (statement_timeout_secs + 5) + round bound"));
    Ok(())
}
