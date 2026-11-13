mod common;
mod memory_support;
mod worst_build;
mod worst_support;


use common::types::TestResult;
use traces_ingest::model::Limits;
use worst_support::{check, DEFAULT_BUDGET_KIB};


const ATTRIBUTES: usize = 3;


const EVENTS: usize = 1;


const LINKS: usize = 1;


const INNER: usize = 1;


#[test]
fn three_attributes_one_attributed_event_and_link_stay_within_the_budget() -> TestResult {
    check(&Limits::default(), DEFAULT_BUDGET_KIB, ATTRIBUTES, EVENTS, LINKS, INNER)
}
