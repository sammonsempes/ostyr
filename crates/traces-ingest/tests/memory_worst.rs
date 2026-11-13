mod common;
mod memory_support;
mod worst_support;


use common::types::TestResult;
use worst_support::check;


const ATTRIBUTES: usize = 3;


const EVENTS: usize = 3;


const LINKS: usize = 3;


#[test]
fn three_attributes_three_events_three_links_stay_within_the_budget() -> TestResult {
    check(ATTRIBUTES, EVENTS, LINKS, 0)
}
