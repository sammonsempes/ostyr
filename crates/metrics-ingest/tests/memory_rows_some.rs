mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use rows::{measure, request};


const SOME_POINTS: usize = 10_000;


const LABELS: usize = 32;


#[test]
fn resource_labels_on_some_points_stay_in_budget() -> TestResult {
    measure("resource labels, some points", &request(SOME_POINTS, LABELS, true), &Limits::default())
}
