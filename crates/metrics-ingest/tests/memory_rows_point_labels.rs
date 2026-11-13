mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use rows::{measure, request};


const POINTS_IN_4_MIB: usize = 300;


const LABELS: usize = 32;


#[test]
fn point_labels_stay_in_budget() -> TestResult {
    measure("point labels", &request(POINTS_IN_4_MIB, LABELS, false), &Limits::default())
}
