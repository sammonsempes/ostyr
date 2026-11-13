mod common;


use cmdb::model::Criticality;
use common::types::TestResult;
use core_config::error::ConfigError;
use remote_shell::error::PolicyError;
use remote_shell::policy::{
    load_policy, parse_policy, policy_of, validate_policy, ShellPolicy, ValidatedPolicy, CEILING_APPROVAL_MAX_AGE_SECONDS,
    CEILING_IDLE_TIMEOUT_SECONDS, CEILING_MAX_DURATION_SECONDS, CEILING_MFA_MAX_AGE_SECONDS, DEFAULT_APPROVAL_MAX_AGE_SECONDS,
    DEFAULT_IDLE_TIMEOUT_SECONDS, DEFAULT_MAX_DURATION_SECONDS, DEFAULT_MFA_MAX_AGE_SECONDS, MAX_POLICY_BYTES,
};
use std::io::{self, Read};


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }
}


const FILE: &str = "policy.yaml";


const FIELDS: [(&str, u64); 4] = [
    ("idle_timeout_seconds", CEILING_IDLE_TIMEOUT_SECONDS),
    ("max_duration_seconds", CEILING_MAX_DURATION_SECONDS),
    ("mfa_max_age_seconds", CEILING_MFA_MAX_AGE_SECONDS),
    ("approval_max_age_seconds", CEILING_APPROVAL_MAX_AGE_SECONDS),
];


const SHORT_IDLE: u64 = 60;


fn parse(text: &str) -> Result<ShellPolicy, PolicyError> {
    parse_policy(&mut text.as_bytes(), FILE).map(|validated| policy_of(&validated).clone())
}


#[test]
fn defaults_are_the_documented_values() -> TestResult {
    let policy = ShellPolicy::default();
    assert_eq!(policy.idle_timeout_seconds, DEFAULT_IDLE_TIMEOUT_SECONDS);
    assert_eq!(policy.max_duration_seconds, DEFAULT_MAX_DURATION_SECONDS);
    assert_eq!(policy.mfa_max_age_seconds, DEFAULT_MFA_MAX_AGE_SECONDS);
    assert_eq!(policy.approval_max_age_seconds, DEFAULT_APPROVAL_MAX_AGE_SECONDS);
    assert_eq!(policy.dual_approval_from, Criticality::Critical);
    Ok(())
}


#[test]
fn a_partial_document_keeps_the_defaults_for_the_rest() -> TestResult {
    let policy = parse(&format!("idle_timeout_seconds: {SHORT_IDLE}\ndual_approval_from: high\n"))?;
    assert_eq!(policy.idle_timeout_seconds, SHORT_IDLE);
    assert_eq!(policy.dual_approval_from, Criticality::High);
    assert_eq!(policy.max_duration_seconds, DEFAULT_MAX_DURATION_SECONDS);
    Ok(())
}


#[test]
fn every_duration_is_accepted_at_its_ceiling() -> TestResult {
    FIELDS
        .iter()
        .try_for_each(|(field, ceiling)| parse(&format!("{field}: {ceiling}\n")).map(|_| ()))?;
    Ok(())
}


#[test]
fn every_duration_refuses_zero_and_anything_above_its_ceiling() -> TestResult {
    FIELDS.iter().try_for_each(|(field, ceiling)| {
        let zero = parse(&format!("{field}: 0\n"));
        let above = parse(&format!("{field}: {}\n", ceiling + 1));
        let named = |result: Result<ShellPolicy, PolicyError>| matches!(result, Err(PolicyError::Invalid { field: found, .. }) if found == *field);
        named(zero)
            .then_some(())
            .and(named(above).then_some(()))
            .ok_or_else(|| io::Error::other(format!("{field} not refused")))
    })?;
    Ok(())
}


#[test]
fn unknown_fields_and_unknown_criticalities_are_refused() -> TestResult {
    assert!(matches!(parse("surprise: 1\n"), Err(PolicyError::Config(ConfigError::Parse { .. }))));
    assert!(matches!(
        parse("dual_approval_from: urgent\n"),
        Err(PolicyError::Config(ConfigError::Parse { .. }))
    ));
    Ok(())
}


#[test]
fn an_oversized_document_is_refused() -> TestResult {
    let big = format!("idle_timeout_seconds: 60\n{}", "x".repeat(usize::try_from(MAX_POLICY_BYTES)?));
    assert!(matches!(parse(&big), Err(PolicyError::Config(ConfigError::TooLarge { .. }))));
    Ok(())
}


#[test]
fn a_failing_reader_is_reported() -> TestResult {
    assert!(matches!(
        parse_policy(&mut FailingReader, FILE),
        Err(PolicyError::Config(ConfigError::Io { .. }))
    ));
    Ok(())
}


#[test]
fn load_policy_reads_a_file_and_reports_a_missing_one() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let path = directory.path().join(FILE);
    std::fs::write(&path, format!("idle_timeout_seconds: {SHORT_IDLE}\n"))?;
    assert_eq!(policy_of(&load_policy(&path)?).idle_timeout_seconds, SHORT_IDLE);
    assert!(matches!(
        load_policy(&directory.path().join("missing.yaml")),
        Err(PolicyError::Config(ConfigError::Io { .. }))
    ));
    Ok(())
}


#[test]
fn an_invalid_field_error_names_the_file_and_the_field() -> TestResult {
    let error = parse("mfa_max_age_seconds: 0\n").err().ok_or("no error")?;
    assert_eq!(error.to_string(), format!("{FILE}: invalid `mfa_max_age_seconds`"));
    Ok(())
}


#[test]
fn a_hand_built_policy_is_validated_before_use() -> TestResult {
    let zero = ShellPolicy {
        idle_timeout_seconds: 0,
        ..ShellPolicy::default()
    };
    assert!(matches!(
        validate_policy(&zero, FILE),
        Err(PolicyError::Invalid {
            field: "idle_timeout_seconds",
            ..
        })
    ));
    let validated: ValidatedPolicy = validate_policy(&ShellPolicy::default(), FILE)?;
    assert_eq!(policy_of(&validated), &ShellPolicy::default());
    assert_eq!(validated, ValidatedPolicy::default());
    Ok(())
}
