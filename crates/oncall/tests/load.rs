#[path = "common/types.rs"]
mod types;


use oncall::error::OncallError;
use oncall::limits::MAX_FILE_BYTES;
use oncall::load::{load_policy, load_schedule, parse_policy, parse_schedule, read_limited};
use oncall::model::{HolidayRule, Target};
use std::io::{self, Read};
use types::TestResult;


const SCHEDULE_YAML: &str = include_str!("fixtures/schedule.yaml");


const POLICY_YAML: &str = include_str!("fixtures/policy.yaml");


const LAYER_COUNT: usize = 2;


const LEVEL_COUNT: usize = 3;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("disk gone"))
    }
}


#[test]
fn a_schedule_file_is_loaded() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("primary.yaml");
    std::fs::write(&path, SCHEDULE_YAML)?;
    let schedule = load_schedule(&path)?;
    assert_eq!(schedule.name, "primary");
    assert_eq!(schedule.time_zone, chrono_tz::Europe::Paris);
    assert_eq!(schedule.layers.len(), LAYER_COUNT);
    assert_eq!(
        schedule.holidays.iter().map(|holiday| holiday.rule.clone()).next_back(),
        Some(HolidayRule::Cover(vec!["dave".to_string()]))
    );
    Ok(())
}


#[test]
fn a_policy_file_is_loaded() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("default.yaml");
    std::fs::write(&path, POLICY_YAML)?;
    let policy = load_policy(&path)?;
    assert_eq!(policy.levels.len(), LEVEL_COUNT);
    assert_eq!(
        policy.levels.iter().flat_map(|level| level.targets.first()).next(),
        Some(&Target::Schedule("primary".to_string()))
    );
    Ok(())
}


#[test]
fn a_missing_file_names_the_path() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("absent.yaml");
    let error = load_schedule(&path).err().ok_or("expected an error")?;
    assert!(error.to_string().contains("absent.yaml"));
    Ok(())
}


#[test]
fn a_parse_error_carries_file_and_line() -> TestResult {
    let text = SCHEDULE_YAML.replace("Europe/Paris", "Mars/Olympus");
    let error = parse_schedule(&text, "bad.yaml").err().ok_or("expected an error")?;
    let shown = error.to_string();
    assert!(shown.starts_with("bad.yaml:2:"), "{shown}");
    assert!(shown.contains("time_zone"), "{shown}");
    Ok(())
}


#[test]
fn unknown_fields_are_refused() -> TestResult {
    let text = format!("{POLICY_YAML}extra: 1\n");
    let error = parse_policy(&text, "policy.yaml").err().ok_or("expected an error")?;
    assert!(matches!(error, OncallError::Config(_)));
    Ok(())
}


#[test]
fn a_parsed_file_over_a_bound_is_refused() -> TestResult {
    let text = POLICY_YAML.replace("delay_seconds: 600", "delay_seconds: 604801");
    let error = parse_policy(&text, "policy.yaml").err().ok_or("expected an error")?;
    assert!(matches!(error, OncallError::OutOfBounds { what: "delay_seconds", .. }));
    let invalid = SCHEDULE_YAML.replace("period_days: 7", "period_days: 0");
    let refused = parse_schedule(&invalid, "schedule.yaml").err().ok_or("expected an error")?;
    assert!(matches!(refused, OncallError::OutOfBounds { what: "period_days", .. }));
    Ok(())
}


#[test]
fn a_file_over_the_size_bound_is_refused() -> TestResult {
    let exact = vec![b'a'; MAX_FILE_BYTES as usize];
    assert_eq!(read_limited(&mut exact.as_slice(), "exact.yaml")?.len() as u64, MAX_FILE_BYTES);
    let over = vec![b'a'; MAX_FILE_BYTES as usize + 1];
    let error = read_limited(&mut over.as_slice(), "big.yaml").err().ok_or("expected an error")?;
    assert!(matches!(error, OncallError::FileTooLarge { .. }));
    assert!(error.to_string().starts_with("big.yaml:"));
    Ok(())
}


#[test]
fn a_failing_reader_is_reported() -> TestResult {
    let error = read_limited(&mut FailingReader, "gone.yaml").err().ok_or("expected an error")?;
    assert!(matches!(error, OncallError::Config(_)));
    assert!(error.to_string().contains("disk gone"));
    Ok(())
}
