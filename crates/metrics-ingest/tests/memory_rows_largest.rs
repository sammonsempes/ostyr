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


const LARGEST_ACCEPTED_POINTS: usize = 2_182;


const LABELS: usize = 32;


#[test]
fn the_largest_accepted_request_stays_in_budget() -> TestResult {
    let bytes = request(
        LARGEST_ACCEPTED_POINTS,
        LABELS,
        true,
        DEFAULT_MAX_LABEL_KEY_BYTES,
        DEFAULT_MAX_LABEL_VALUE_BYTES,
        None,
    );
    let (rows, accepted) = measure("largest accepted", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (LARGEST_ACCEPTED_POINTS, true));
    Ok(())
}
