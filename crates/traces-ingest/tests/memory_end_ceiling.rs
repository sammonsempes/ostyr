mod common;
mod end_support;
mod memory_support;
mod worst_build;


use common::types::TestResult;
use end_support::check_end_to_end;
use traces_ingest::settings::ceiling_limits;


const BUDGET_KIB: u64 = 524_288;


#[test]
fn the_worst_accepted_request_through_run_insert_stays_within_512_mib_at_the_ceilings() -> TestResult {
    check_end_to_end(&ceiling_limits(), BUDGET_KIB, None)
}
