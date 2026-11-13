mod common;
mod memory_support;
mod worst_support;


use common::types::TestResult;
use worst_support::check;


const ATTRIBUTES: usize = 2;


const EVENTS: usize = 2;


const LINKS: usize = 2;


#[test]
fn two_attributes_two_events_two_links_stay_within_the_budget() -> TestResult {
    check(ATTRIBUTES, EVENTS, LINKS)
}
