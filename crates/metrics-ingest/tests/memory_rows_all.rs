mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use rows::{measure, request};


const ALL_POINTS: usize = 49_999;


const LABELS: usize = 32;


#[test]
fn resource_labels_on_every_point_stay_in_budget() -> TestResult {
    measure("resource labels, all points", &request(ALL_POINTS, LABELS, true), &Limits::default())
}
