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


const KEY_WIDTH: usize = 2;


#[test]
fn empty_values_at_every_point_stay_in_budget() -> TestResult {
    let bytes = request(ALL_POINTS, LABELS, true, KEY_WIDTH, 0);
    let (rows, accepted) = measure("empty values", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (0, false));
    Ok(())
}


#[test]
fn no_labels_at_every_point_stay_in_budget() -> TestResult {
    let bytes = request(ALL_POINTS, 0, true, KEY_WIDTH, 0);
    let (rows, accepted) = measure("no labels", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (ALL_POINTS, true));
    Ok(())
}
