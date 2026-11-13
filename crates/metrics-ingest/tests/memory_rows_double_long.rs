mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use rows::{measure, request};


const POINTS: usize = 2_849;


const LABELS: usize = 32;


const KEY_WIDTH: usize = 2;


const DOUBLE: f64 = 1e-131;


#[test]
fn long_double_point_labels_at_the_most_points_the_budget_admits_stay_in_budget() -> TestResult {
    let bytes = request(POINTS, LABELS, false, KEY_WIDTH, 0, Some(DOUBLE));
    let (rows, accepted) = measure("double 1e-131 point labels", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (POINTS, true));
    Ok(())
}
