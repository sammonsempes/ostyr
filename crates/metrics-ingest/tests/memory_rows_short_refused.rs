mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use rows::{measure, request};


const PAST_THE_BUDGET_POINTS: usize = 12_000;


const LABELS: usize = 32;


const KEY_WIDTH: usize = 2;


const VALUE_WIDTH: usize = 1;


#[test]
fn short_labels_past_the_budget_are_refused() -> TestResult {
    let bytes = request(PAST_THE_BUDGET_POINTS, LABELS, true, KEY_WIDTH, VALUE_WIDTH, None);
    let (rows, accepted) = measure("short labels, past the budget", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (0, false));
    Ok(())
}
