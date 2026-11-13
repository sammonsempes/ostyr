mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use rows::{measure, request};


const LARGEST_ACCEPTED_POINTS: usize = 2_412;


const LABELS: usize = 32;


#[test]
fn the_largest_accepted_request_stays_in_budget() -> TestResult {
    measure("largest accepted", &request(LARGEST_ACCEPTED_POINTS, LABELS, true), &Limits::default())
}
