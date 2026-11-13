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


const POINTS: usize = 2_849;


const LABELS: usize = 32;


const KEY_WIDTH: usize = 2;


const FILLER_SCOPE_ATTRIBUTES: usize = 0;


#[test]
fn distinct_long_double_series_past_the_budget_are_refused() -> TestResult {
    let bytes = request_distinct(POINTS, LABELS, KEY_WIDTH, FILLER_SCOPE_ATTRIBUTES)?;
    let (rows, accepted) = measure("distinct long doubles, past the budget", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (0, false));
    Ok(())
}
