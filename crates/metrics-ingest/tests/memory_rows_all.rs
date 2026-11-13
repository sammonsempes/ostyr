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
use metrics_ingest::model::{DEFAULT_MAX_LABEL_KEY_BYTES, DEFAULT_MAX_LABEL_VALUE_BYTES};
use rows::request;


const ALL_POINTS: usize = 49_999;


const LABELS: usize = 32;


#[test]
fn resource_labels_on_every_point_stay_in_budget() -> TestResult {
    let (rows, accepted) = measure(
        "resource labels, all points",
        &request(ALL_POINTS, LABELS, true, DEFAULT_MAX_LABEL_KEY_BYTES, DEFAULT_MAX_LABEL_VALUE_BYTES, None),
        &Limits::default(),
        1,
    )?;
    assert_eq!((rows, accepted), (0, false));
    Ok(())
}
