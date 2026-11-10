#[path = "common/types.rs"]
mod types;


use synthetic_checks::decision::{certificate_threshold, check_result, excerpt, location_failing, should_alert};
use synthetic_checks::model::{CertificateDay, Check, CheckKind, FailureRun, LocationHistory, DEFAULT_CERT_DAYS, MAX_BODY_EXCERPT_BYTES};
use types::TestResult;


const THREE: u64 = 3;


const TWO: u64 = 2;


const BIG_BODY: usize = 100_000;


const INTERVAL: u64 = 60;


const TIMEOUT: u64 = 10;


const ABOVE_ALL: i64 = 31;


const HIGH: u64 = 30;


const MIDDLE: u64 = 14;


const LOW: u64 = 7;


const BETWEEN_HIGH_AND_MIDDLE: i64 = 20;


const BETWEEN_MIDDLE_AND_LOW: i64 = 8;


const NEAR_EXPIRY: i64 = 3;


fn run(count: u64) -> Result<FailureRun, Box<dyn std::error::Error>> {
    Ok(FailureRun::try_from(count)?)
}


fn days(values: &[u64]) -> Result<Vec<CertificateDay>, Box<dyn std::error::Error>> {
    Ok(values
        .iter()
        .map(|value| CertificateDay::try_from(*value))
        .collect::<Result<Vec<_>, _>>()?)
}


fn check(min_failing_locations: u64) -> Result<Check, Box<dyn std::error::Error>> {
    Ok(Check {
        name: "web".to_string(),
        kind: CheckKind::Http,
        target: "https://example.org/".to_string(),
        interval_seconds: INTERVAL,
        timeout_seconds: TIMEOUT,
        consecutive_failures: run(THREE)?,
        locations: vec!["paris".to_string(), "berlin".to_string()],
        min_failing_locations,
        certificate_days: days(&DEFAULT_CERT_DAYS)?,
        nat64_prefix: None,
    })
}


fn history(location: &str, results: &[bool]) -> LocationHistory {
    LocationHistory {
        location: location.to_string(),
        results: results.to_vec(),
    }
}


#[test]
fn consecutive_failures_are_required() -> TestResult {
    assert!(location_failing(&history("p", &[true, false, false, false]), run(THREE)?));
    assert!(!location_failing(&history("p", &[false, false]), run(THREE)?));
    Ok(())
}


#[test]
fn a_success_resets_the_run() -> TestResult {
    assert!(!location_failing(&history("p", &[false, false, true]), run(THREE)?));
    assert!(!location_failing(&history("p", &[false, false, true, false, false]), run(THREE)?));
    Ok(())
}


#[test]
fn quorum_of_locations() -> TestResult {
    let down = [false, false, false];
    let both = [history("paris", &down), history("berlin", &down)];
    let one = [history("paris", &down), history("berlin", &[true])];
    assert!(should_alert(&check(TWO)?, &both));
    assert!(!should_alert(&check(TWO)?, &one));
    assert!(should_alert(&check(1)?, &one));
    assert!(!should_alert(&check(1)?, &[]));
    Ok(())
}


#[test]
fn undeclared_locations_do_not_count() -> TestResult {
    let down = [false, false, false];
    assert!(!should_alert(&check(1)?, &[history("tokyo", &down)]));
    Ok(())
}


#[test]
fn each_certificate_threshold() -> TestResult {
    let cases = [
        (ABOVE_ALL, None),
        (HIGH as i64, Some(HIGH)),
        (BETWEEN_HIGH_AND_MIDDLE, Some(HIGH)),
        (MIDDLE as i64, Some(MIDDLE)),
        (BETWEEN_MIDDLE_AND_LOW, Some(MIDDLE)),
        (LOW as i64, Some(LOW)),
        (1, Some(LOW)),
        (-NEAR_EXPIRY, Some(LOW)),
    ];
    let thresholds = days(&DEFAULT_CERT_DAYS)?;
    cases.iter().for_each(|(days_left, expected)| {
        assert_eq!(certificate_threshold(&thresholds, *days_left), *expected, "{days_left}");
    });
    assert_eq!(certificate_threshold(&[], 1), None);
    Ok(())
}


#[test]
fn excerpt_is_capped() -> TestResult {
    assert_eq!(excerpt(b"hello"), "hello");
    assert_eq!(excerpt(&vec![b'a'; BIG_BODY]).len(), MAX_BODY_EXCERPT_BYTES);
    Ok(())
}


#[test]
fn excerpt_cap_never_splits_a_character() -> TestResult {
    let body = "é".repeat(MAX_BODY_EXCERPT_BYTES);
    assert_eq!(excerpt(body.as_bytes()).len(), MAX_BODY_EXCERPT_BYTES);
    let odd = format!("a{}", "é".repeat(MAX_BODY_EXCERPT_BYTES));
    assert!(excerpt(odd.as_bytes()).len() <= MAX_BODY_EXCERPT_BYTES);
    Ok(())
}


#[test]
fn result_keeps_only_the_excerpt() -> TestResult {
    let result = check_result("web", "paris", false, &vec![b'x'; BIG_BODY]);
    assert_eq!(result.check, "web");
    assert_eq!(result.location, "paris");
    assert!(!result.succeeded);
    assert_eq!(result.body_excerpt.len(), MAX_BODY_EXCERPT_BYTES);
    Ok(())
}
