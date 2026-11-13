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


const KEY_WIDTH: usize = 2;


#[test]
fn no_labels_at_every_point_stay_in_budget() -> TestResult {
    let bytes = request(ALL_POINTS, 0, true, KEY_WIDTH, 0, None);
    let (rows, accepted) = measure("no labels", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (ALL_POINTS, true));
    Ok(())
}
