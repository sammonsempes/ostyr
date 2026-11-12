use crate::suite::common::{TestResult, MAX_BYTES, THRESHOLDS};
use app_health::assess::assess;
use app_health::measures::measures;
use app_health::model::{BlindReason, LeapStatus, NtpHealth};
use app_health::parse::{parse_chrony_tracking, parse_timedatectl};


const LAB_UNSYNC: &str = include_str!("../fixtures/lab-tracking-unsync.csv");


const LAB_SKEWED: &str = include_str!("../fixtures/lab-tracking-skewed.csv");


const LAB_TIMEDATECTL: &str = include_str!("../fixtures/lab-timedatectl.txt");


const LAB_TIMEZONE: &str = "Etc/UTC";


const MEASURE_COUNT: usize = 4;


#[test]
fn lab_capture_without_a_source_is_a_blind_spot() -> TestResult {
    let tracking = parse_chrony_tracking(LAB_UNSYNC.as_bytes(), MAX_BYTES)?;
    let state = parse_timedatectl(LAB_TIMEDATECTL.as_bytes(), MAX_BYTES)?;
    assert_eq!(tracking.leap_status, LeapStatus::NotSynchronised);
    assert_eq!(state.synchronized, Some(false));
    assert_eq!(state.timezone.as_deref(), Some(LAB_TIMEZONE));
    assert_eq!(
        assess(&tracking, Some(&state), &THRESHOLDS),
        NtpHealth::BlindSpot(BlindReason::NotSynchronised)
    );
    assert_eq!(measures(&tracking).len(), MEASURE_COUNT);
    Ok(())
}


#[test]
fn lab_capture_after_a_clock_step_is_never_healthy() -> TestResult {
    let tracking = parse_chrony_tracking(LAB_SKEWED.as_bytes(), MAX_BYTES)?;
    assert_ne!(assess(&tracking, None, &THRESHOLDS), NtpHealth::Healthy);
    Ok(())
}
