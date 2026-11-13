mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;
#[path = "memory_support/rows.rs"]
mod rows;


use common::types::TestResult;
use metrics_ingest::model::Limits;
use metrics_ingest::model::{DEFAULT_MAX_LABEL_KEY_BYTES, DEFAULT_MAX_LABEL_VALUE_BYTES};
use metrics_ingest::settings::MAX_ROW_BYTES_TOTAL_CEILING;
use rows::{measure, request};


const LARGEST_ACCEPTED_POINTS: usize = 2_200;


const LARGEST_CEILING_POINTS: usize = 22_000;


const CEILING_FACTOR: u64 = 10;


const LABELS: usize = 32;


#[test]
fn the_largest_accepted_request_stays_in_budget() -> TestResult {
    let bytes = request(
        LARGEST_ACCEPTED_POINTS,
        LABELS,
        true,
        DEFAULT_MAX_LABEL_KEY_BYTES,
        DEFAULT_MAX_LABEL_VALUE_BYTES,
    );
    let (rows, accepted) = measure("largest accepted", &bytes, &Limits::default(), 1)?;
    assert_eq!((rows, accepted), (LARGEST_ACCEPTED_POINTS, true));
    Ok(())
}


#[test]
fn the_largest_accepted_request_at_the_ceiling_stays_under_ten_times() -> TestResult {
    let limits = Limits {
        max_row_bytes_total: usize::try_from(MAX_ROW_BYTES_TOTAL_CEILING)?,
        ..Limits::default()
    };
    let bytes = request(
        LARGEST_CEILING_POINTS,
        LABELS,
        true,
        DEFAULT_MAX_LABEL_KEY_BYTES,
        DEFAULT_MAX_LABEL_VALUE_BYTES,
    );
    let (rows, accepted) = measure("largest at ceiling", &bytes, &limits, CEILING_FACTOR)?;
    assert_eq!((rows, accepted), (LARGEST_CEILING_POINTS, true));
    Ok(())
}
