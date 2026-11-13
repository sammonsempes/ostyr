mod common;
mod memory_support;
mod worst_support;


use common::types::TestResult;
use worst_support::check;


const ATTRIBUTES: usize = 1;


const EVENTS: usize = 2;


const LINKS: usize = 2;


const INNER: usize = 1;


#[test]
fn one_attribute_two_attributed_events_and_links_stay_within_the_budget() -> TestResult {
    check(ATTRIBUTES, EVENTS, LINKS, INNER)
}
