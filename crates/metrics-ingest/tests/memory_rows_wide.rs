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


const WIDE_LABELS: usize = 64;


#[test]
fn wide_resource_labels_stay_in_budget() -> TestResult {
    let limits = Limits {
        max_labels: WIDE_LABELS,
        ..Limits::default()
    };
    measure("64 resource labels", &request(ALL_POINTS, WIDE_LABELS, true), &limits)
}
