mod common;
#[path = "memory_support/measure.rs"]
mod measure;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use measure::measure;
use metrics_ingest::model::Limits;
use rows::request;


const POINTS: usize = 3_500;


const LABELS: usize = 32;


const KEY_WIDTH: usize = 2;


const DOUBLE: f64 = 1e-131;


#[test]
fn long_double_point_labels_past_the_budget_are_refused() -> TestResult {
    let bytes = request(POINTS, LABELS, false, KEY_WIDTH, 0, Some(DOUBLE));
    let (rows, accepted) = measure("double 1e-131 point labels, past the budget", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (0, false));
    Ok(())
}
