mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use metrics_ingest::model::{DEFAULT_MAX_LABEL_KEY_BYTES, DEFAULT_MAX_LABEL_VALUE_BYTES};
use rows::{measure, request};


const POINTS_IN_4_MIB: usize = 300;


const LABELS: usize = 32;


const ACCEPTED_ROWS: usize = 300;


#[test]
fn point_labels_stay_in_budget() -> TestResult {
    let (rows, accepted) = measure(
        "point labels",
        &request(
            POINTS_IN_4_MIB,
            LABELS,
            false,
            DEFAULT_MAX_LABEL_KEY_BYTES,
            DEFAULT_MAX_LABEL_VALUE_BYTES,
            None,
        ),
        &Limits::default(),
        1,
    )?;
    assert_eq!((rows, accepted), (ACCEPTED_ROWS, true));
    Ok(())
}
