use crate::suite::common::{tracking, TestResult, MAX_BYTES, SYNCHRONISED};
use app_health::measures::measures;
use app_health::model::LeapStatus;
use app_health::parse::parse_chrony_tracking;


const EXPECTED_OFFSET: f64 = 0.000012345;


const EXPECTED_FREQUENCY: f64 = 1.234;


const EXPECTED_STRATUM: f64 = 3.0;


const EXPECTED_DISPERSION: f64 = 0.001;


#[test]
fn four_measures_from_a_full_capture() -> TestResult {
    let sample = parse_chrony_tracking(SYNCHRONISED.as_bytes(), MAX_BYTES)?;
    let found: Vec<(&str, &str, f64)> = measures(&sample).iter().map(|item| (item.name, item.unit, item.value)).collect();
    let expected = vec![
        ("ntp.offset", "s", EXPECTED_OFFSET),
        ("ntp.frequency", "ppm", EXPECTED_FREQUENCY),
        ("ntp.stratum", "1", EXPECTED_STRATUM),
        ("ntp.root_dispersion", "s", EXPECTED_DISPERSION),
    ];
    assert_eq!(found, expected);
    Ok(())
}


#[test]
fn missing_values_yield_no_measure() -> TestResult {
    let sample = tracking(None, None, LeapStatus::Normal);
    assert!(measures(&sample).is_empty());
    Ok(())
}
