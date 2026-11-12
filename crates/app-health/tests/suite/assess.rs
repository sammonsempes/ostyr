use crate::suite::common::{tracking, TestResult, LIMIT_OFFSET, LIMIT_STRATUM, MAX_BYTES, SYNCHRONISED, THRESHOLDS, UNSYNCHRONISED};
use app_health::assess::assess;
use app_health::model::{BlindReason, LeapStatus, NtpHealth, Thresholds, TimeSync};
use app_health::parse::parse_chrony_tracking;


const ABOVE_LIMIT: f64 = 0.500001;


const STRATUM_SIXTEEN: u32 = 16;


const FAR_OFFSET: f64 = 99.0;


const NO_OFFSET: f64 = 0.0;


fn sync(synchronized: Option<bool>) -> TimeSync {
    TimeSync {
        ntp_enabled: Some(true),
        synchronized,
        timezone: None,
        rejected_fields: 0,
    }
}


#[test]
fn healthy_at_the_boundaries() -> TestResult {
    let sample = tracking(Some(LIMIT_OFFSET), Some(LIMIT_STRATUM), LeapStatus::Normal);
    assert_eq!(assess(&sample, Some(&sync(Some(true))), &THRESHOLDS), NtpHealth::Healthy);
    let negative = tracking(Some(-LIMIT_OFFSET), Some(1), LeapStatus::InsertSecond);
    assert_eq!(assess(&negative, None, &THRESHOLDS), NtpHealth::Healthy);
    Ok(())
}


#[test]
fn drift_in_both_directions() -> TestResult {
    [ABOVE_LIMIT, -ABOVE_LIMIT].iter().for_each(|offset| {
        let sample = tracking(Some(*offset), Some(1), LeapStatus::Normal);
        assert_eq!(assess(&sample, None, &THRESHOLDS), NtpHealth::Drift { offset: *offset });
    });
    Ok(())
}


#[test]
fn stratum_above_the_limit() -> TestResult {
    let sample = tracking(Some(NO_OFFSET), Some(LIMIT_STRATUM + 1), LeapStatus::DeleteSecond);
    assert_eq!(assess(&sample, None, &THRESHOLDS), NtpHealth::Stratum { stratum: LIMIT_STRATUM + 1 });
    let sixteen = tracking(Some(NO_OFFSET), Some(STRATUM_SIXTEEN), LeapStatus::Normal);
    assert_eq!(assess(&sixteen, None, &THRESHOLDS), NtpHealth::Stratum { stratum: STRATUM_SIXTEEN });
    Ok(())
}


#[test]
fn unsynchronised_only_when_required() -> TestResult {
    let sample = tracking(Some(NO_OFFSET), Some(1), LeapStatus::Normal);
    assert_eq!(assess(&sample, Some(&sync(Some(false))), &THRESHOLDS), NtpHealth::Unsynchronised);
    let relaxed = Thresholds {
        require_synchronized: false,
        ..THRESHOLDS
    };
    assert_eq!(assess(&sample, Some(&sync(Some(false))), &relaxed), NtpHealth::Healthy);
    assert_eq!(assess(&sample, Some(&sync(None)), &THRESHOLDS), NtpHealth::Healthy);
    Ok(())
}


#[test]
fn missing_stratum_is_not_a_stratum_verdict() -> TestResult {
    let sample = tracking(Some(NO_OFFSET), None, LeapStatus::Normal);
    assert_eq!(assess(&sample, None, &THRESHOLDS), NtpHealth::Healthy);
    Ok(())
}


#[test]
fn blind_spots() -> TestResult {
    let unsync = tracking(Some(FAR_OFFSET), Some(STRATUM_SIXTEEN), LeapStatus::NotSynchronised);
    assert_eq!(
        assess(&unsync, Some(&sync(Some(false))), &THRESHOLDS),
        NtpHealth::BlindSpot(BlindReason::NotSynchronised)
    );
    let missing = tracking(None, Some(STRATUM_SIXTEEN), LeapStatus::Normal);
    assert_eq!(
        assess(&missing, Some(&sync(Some(false))), &THRESHOLDS),
        NtpHealth::BlindSpot(BlindReason::NoOffset)
    );
    Ok(())
}


#[test]
fn precedence_drift_over_stratum_over_unsynchronised() -> TestResult {
    let both = tracking(Some(ABOVE_LIMIT), Some(STRATUM_SIXTEEN), LeapStatus::Normal);
    assert_eq!(
        assess(&both, Some(&sync(Some(false))), &THRESHOLDS),
        NtpHealth::Drift { offset: ABOVE_LIMIT }
    );
    let stratum_and_unsync = tracking(Some(NO_OFFSET), Some(STRATUM_SIXTEEN), LeapStatus::Normal);
    assert_eq!(
        assess(&stratum_and_unsync, Some(&sync(Some(false))), &THRESHOLDS),
        NtpHealth::Stratum { stratum: STRATUM_SIXTEEN }
    );
    Ok(())
}


#[test]
fn fixtures_assess_end_to_end() -> TestResult {
    let good = parse_chrony_tracking(SYNCHRONISED.as_bytes(), MAX_BYTES)?;
    assert_eq!(assess(&good, None, &THRESHOLDS), NtpHealth::Healthy);
    let bad = parse_chrony_tracking(UNSYNCHRONISED.as_bytes(), MAX_BYTES)?;
    assert_eq!(assess(&bad, None, &THRESHOLDS), NtpHealth::BlindSpot(BlindReason::NotSynchronised));
    Ok(())
}
