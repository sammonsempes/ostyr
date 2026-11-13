mod common;
mod end_support;
mod memory_support;
mod worst_build;


use common::types::TestResult;
use end_support::check_end_to_end;
use traces_ingest::model::Limits;


const BUDGET_KIB: u64 = 131_072;


#[test]
fn the_worst_accepted_request_through_run_insert_stays_within_128_mib_at_defaults() -> TestResult {
    check_end_to_end(&Limits::default(), BUDGET_KIB, None)
}
