mod common;
mod memory_support;
mod worst_support;


use common::types::TestResult;
use traces_ingest::model::Limits;
use worst_support::{check, DEFAULT_BUDGET_KIB};


const ATTRIBUTES: usize = 1;


const EVENTS: usize = 2;


const LINKS: usize = 2;


const INNER: usize = 1;


#[test]
fn one_attribute_two_attributed_events_and_links_stay_within_the_budget() -> TestResult {
    check(&Limits::default(), DEFAULT_BUDGET_KIB, ATTRIBUTES, EVENTS, LINKS, INNER)
}
