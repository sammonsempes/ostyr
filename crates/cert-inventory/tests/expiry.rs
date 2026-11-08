#[path = "common/record.rs"]
mod record;
#[path = "common/types.rs"]
mod types;


use cert_inventory::expiry::{expiry_state, SECONDS_PER_DAY};
use cert_inventory::model::ExpiryState;
use record::record_with;
use types::TestResult;


const NOW: i64 = 1_000_000;


const DAYS_FAR: i64 = 31;


const DAYS_MONTH: i64 = 30;


const DAYS_BETWEEN: i64 = 8;


const DAYS_WEEK: i64 = 7;


const THRESHOLD_MONTH: u32 = 30;


const THRESHOLD_WEEK: u32 = 7;


const THRESHOLDS: [u32; 3] = [THRESHOLD_MONTH, THRESHOLD_WEEK, 1];


#[test]
fn far_expiry_is_valid() -> TestResult {
    let record = record_with(&[], NOW + DAYS_FAR * SECONDS_PER_DAY);
    assert_eq!(expiry_state(&record, NOW, &THRESHOLDS), ExpiryState::Valid);
    Ok(())
}


#[test]
fn each_threshold_is_reported() -> TestResult {
    let at = |days: i64, extra: i64| expiry_state(&record_with(&[], NOW + days * SECONDS_PER_DAY + extra), NOW, &THRESHOLDS);
    assert_eq!(
        at(DAYS_MONTH, 0),
        ExpiryState::Crossed {
            threshold_days: THRESHOLD_MONTH
        }
    );
    assert_eq!(
        at(DAYS_BETWEEN, 0),
        ExpiryState::Crossed {
            threshold_days: THRESHOLD_MONTH
        }
    );
    assert_eq!(
        at(DAYS_WEEK, 0),
        ExpiryState::Crossed {
            threshold_days: THRESHOLD_WEEK
        }
    );
    assert_eq!(
        at(1, 1),
        ExpiryState::Crossed {
            threshold_days: THRESHOLD_WEEK
        }
    );
    assert_eq!(at(1, 0), ExpiryState::Crossed { threshold_days: 1 });
    Ok(())
}


#[test]
fn expiry_instant_and_past_are_expired() -> TestResult {
    assert_eq!(expiry_state(&record_with(&[], NOW), NOW, &THRESHOLDS), ExpiryState::Expired);
    assert_eq!(expiry_state(&record_with(&[], NOW - 1), NOW, &THRESHOLDS), ExpiryState::Expired);
    Ok(())
}


#[test]
fn no_thresholds_means_valid_until_expiry() -> TestResult {
    assert_eq!(expiry_state(&record_with(&[], NOW + 1), NOW, &[]), ExpiryState::Valid);
    Ok(())
}
