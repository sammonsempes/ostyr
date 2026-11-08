mod common;


use cases::error::{SlaError, SlaLoadError};
use cases::model::Severity;
use cases::sla::{load_sla, sla_minutes, sla_state, validate_sla, SlaSettings, SlaState, MAX_NEAR_PERCENT, MAX_SLA_MINUTES};
use common::types::TestResult;
use std::fs;
use tempfile::tempdir;


const LOW: u32 = 1_440;


const MEDIUM: u32 = 480;


const HIGH: u32 = 60;


const CRITICAL: u32 = 15;


const MIN: u32 = 1;


const MAX: u32 = 2;


const CREATED: i64 = 1_800_000_000;


const SETTINGS: SlaSettings = SlaSettings {
    low_minutes: LOW,
    medium_minutes: MEDIUM,
    high_minutes: HIGH,
    critical_minutes: CRITICAL,
    near_percent: 80,
};


const CRITICAL_LIMIT: i64 = 900;


const CRITICAL_NEAR: i64 = 720;


#[test]
fn boundaries_with_a_frozen_clock() -> TestResult {
    let state_at = |elapsed: i64| sla_state(CREATED, Severity::Critical, &SETTINGS, CREATED + elapsed);
    assert_eq!(state_at(0), SlaState::Within);
    assert_eq!(state_at(CRITICAL_NEAR - 1), SlaState::Within);
    assert_eq!(state_at(CRITICAL_NEAR), SlaState::Near);
    assert_eq!(state_at(CRITICAL_LIMIT - 1), SlaState::Near);
    assert_eq!(state_at(CRITICAL_LIMIT), SlaState::Past);
    assert_eq!(state_at(CRITICAL_LIMIT + 1), SlaState::Past);
    Ok(())
}


#[test]
fn a_clock_behind_the_creation_is_within() -> TestResult {
    assert_eq!(sla_state(CREATED, Severity::Critical, &SETTINGS, CREATED - 1), SlaState::Within);
    assert_eq!(sla_state(i64::MAX, Severity::Low, &SETTINGS, i64::MIN), SlaState::Within);
    Ok(())
}


#[test]
fn each_severity_has_its_delay() -> TestResult {
    let minutes: Vec<u32> = [Severity::Low, Severity::Medium, Severity::High, Severity::Critical]
        .iter()
        .map(|severity| sla_minutes(&SETTINGS, *severity))
        .collect();
    assert_eq!(minutes, [LOW, MEDIUM, HIGH, CRITICAL]);
    Ok(())
}


#[test]
fn bounds_are_enforced_on_every_field() -> TestResult {
    assert_eq!(validate_sla(SETTINGS), Ok(SETTINGS));
    let invalid = |settings: SlaSettings, field: &str| match validate_sla(settings) {
        Err(SlaError::OutOfRange { field: found, .. }) => found == field,
        Ok(_) => false,
    };
    assert!(invalid(SlaSettings { low_minutes: 0, ..SETTINGS }, "low_minutes"));
    assert!(invalid(
        SlaSettings {
            medium_minutes: 0,
            ..SETTINGS
        },
        "medium_minutes"
    ));
    assert!(invalid(
        SlaSettings {
            high_minutes: MAX_SLA_MINUTES + 1,
            ..SETTINGS
        },
        "high_minutes"
    ));
    assert!(invalid(
        SlaSettings {
            critical_minutes: 0,
            ..SETTINGS
        },
        "critical_minutes"
    ));
    assert!(invalid(SlaSettings { near_percent: 0, ..SETTINGS }, "near_percent"));
    assert!(invalid(
        SlaSettings {
            near_percent: MAX_NEAR_PERCENT + 1,
            ..SETTINGS
        },
        "near_percent"
    ));
    assert!(validate_sla(SlaSettings {
        critical_minutes: MAX_SLA_MINUTES,
        near_percent: MAX_NEAR_PERCENT,
        ..SETTINGS
    })
    .is_ok());
    Ok(())
}


#[test]
fn out_of_range_message_names_the_field() -> TestResult {
    let message = SlaError::OutOfRange {
        field: "low_minutes",
        value: 0,
        min: MIN,
        max: MAX,
    }
    .to_string();
    assert!(message.contains("low_minutes"));
    Ok(())
}


#[test]
fn settings_load_from_yaml() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("sla.yaml");
    fs::write(
        &path,
        "low_minutes: 1440\nmedium_minutes: 480\nhigh_minutes: 60\ncritical_minutes: 15\nnear_percent: 80\n",
    )?;
    assert_eq!(load_sla(&path)?, SETTINGS);
    Ok(())
}


#[test]
fn unknown_field_names_file_and_line() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("sla.yaml");
    fs::write(
        &path,
        "low_minutes: 1\nmedium_minutes: 1\nhigh_minutes: 1\ncritical_minutes: 1\nnear_percent: 50\nextra: 1\n",
    )?;
    let message = load_sla(&path).err().ok_or("expected an error")?.to_string();
    assert!(message.contains("sla.yaml:6"), "{message}");
    assert!(message.contains("extra"), "{message}");
    Ok(())
}


#[test]
fn out_of_range_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("sla.yaml");
    fs::write(
        &path,
        "low_minutes: 0\nmedium_minutes: 1\nhigh_minutes: 1\ncritical_minutes: 1\nnear_percent: 50\n",
    )?;
    assert!(matches!(load_sla(&path), Err(SlaLoadError::Invalid(SlaError::OutOfRange { .. }))));
    Ok(())
}
