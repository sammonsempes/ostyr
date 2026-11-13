mod common;
#[path = "memory_support/distinct.rs"]
mod distinct;
#[path = "memory_support/measure.rs"]
mod measure;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;


use common::types::TestResult;
use distinct::request_distinct;
use measure::measure;
use metrics_ingest::model::Limits;


const POINTS: usize = 1_394;


const LABELS: usize = 32;


const KEY_WIDTH: usize = 2;


const FILLER_SCOPE_ATTRIBUTES: usize = 158_000;


#[test]
fn distinct_long_double_series_with_filler_scope_attributes_stay_in_budget() -> TestResult {
    let bytes = request_distinct(POINTS, LABELS, KEY_WIDTH, FILLER_SCOPE_ATTRIBUTES)?;
    let (rows, accepted) = measure("distinct long doubles with filler scope attributes", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (POINTS, true));
    Ok(())
}
