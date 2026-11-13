mod common;
mod memory_support;
mod worst_build;
mod worst_support;


use common::types::TestResult;
use traces_ingest::model::Limits;
use worst_support::{check, DEFAULT_BUDGET_KIB};


const ATTRIBUTES: usize = 2;


const EVENTS: usize = 2;


const LINKS: usize = 2;


#[test]
fn two_attributes_two_events_two_links_stay_within_the_budget() -> TestResult {
    check(&Limits::default(), DEFAULT_BUDGET_KIB, ATTRIBUTES, EVENTS, LINKS, 0)
}
