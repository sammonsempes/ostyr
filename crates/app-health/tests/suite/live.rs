use crate::suite::common::{TestResult, MAX_BYTES, THRESHOLDS};
use app_health::assess::assess;
use app_health::journal::log_excerpt;
use app_health::measures::measures;
use app_health::model::UnitHealth;
use app_health::model::{BlindReason, LeapStatus, NtpHealth};
use app_health::parse::{parse_chrony_tracking, parse_timedatectl};
use app_health::units::{assess_unit, load_expectations, parse_unit_show};


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


const UNIT_FLAP: &str = "t334-flap.service";


const UNIT_STEADY: &str = "t334-steady.service";


const UNIT_MISSING: &str = "t334-missing.service";


const LAB_UNITS: &str = include_str!("../fixtures/units.yaml");


const LAB_FLAP_1: &str = include_str!("../fixtures/lab-unit-flap-1.txt");


const LAB_FLAP_2: &str = include_str!("../fixtures/lab-unit-flap-2.txt");


const LAB_RUNNING: &str = include_str!("../fixtures/lab-unit-steady-running.txt");


const LAB_STOPPED: &str = include_str!("../fixtures/lab-unit-steady-stopped.txt");


const LAB_MISSING: &str = include_str!("../fixtures/lab-unit-missing.txt");


const LAB_EVIL_JOURNAL: &str = include_str!("../fixtures/lab-journal-evil.txt");


const LAB_FLAP_JOURNAL: &str = include_str!("../fixtures/lab-journal-flap.txt");


const LAB_FLAP_GROWTH: u32 = 7;


const JOURNAL_LINES: usize = 20;


const LINE_CAP: usize = 512;


const EVIL_LINE: &str = "esc\\u{1b}[31mred bidi\\u{202e}txt";


fn lab_health(unit: &str, previous: Option<&str>, current: &str) -> Result<UnitHealth, Box<dyn std::error::Error>> {
    let expectations = load_expectations(LAB_UNITS, "units.yaml")?;
    let expectation = expectations.iter().find(|item| item.unit == unit).ok_or("no expectation")?;
    let before = previous.map(|text| parse_unit_show(text.as_bytes(), MAX_BYTES, unit)).transpose()?;
    let now = parse_unit_show(current.as_bytes(), MAX_BYTES, unit)?;
    Ok(assess_unit(expectation, before.as_ref(), &now))
}


#[test]
fn lab_flapping_unit_is_flapping() -> TestResult {
    let health = lab_health(UNIT_FLAP, Some(LAB_FLAP_1), LAB_FLAP_2)?;
    assert_eq!(health, UnitHealth::Flapping { restarts: LAB_FLAP_GROWTH });
    let excerpt = log_excerpt(LAB_FLAP_JOURNAL.as_bytes(), JOURNAL_LINES, LINE_CAP)?;
    assert_eq!(excerpt.lines.len(), JOURNAL_LINES);
    assert!(excerpt.lines.iter().any(|line| line == "flap-failure-line"));
    Ok(())
}


#[test]
fn lab_stopped_and_missing_units() -> TestResult {
    assert_eq!(lab_health(UNIT_STEADY, None, LAB_RUNNING)?, UnitHealth::Healthy);
    assert_eq!(lab_health(UNIT_STEADY, None, LAB_STOPPED)?, UnitHealth::Stopped);
    assert_eq!(lab_health(UNIT_MISSING, None, LAB_MISSING)?, UnitHealth::NotFound);
    Ok(())
}


#[test]
fn lab_journal_with_escape_and_bidi_is_escaped() -> TestResult {
    let excerpt = log_excerpt(LAB_EVIL_JOURNAL.as_bytes(), JOURNAL_LINES, LINE_CAP)?;
    assert!(excerpt.lines.iter().any(|line| line == EVIL_LINE));
    assert!(excerpt.lines.iter().all(|line| !line.contains('\u{1b}') && !line.contains('\u{202e}')));
    Ok(())
}
