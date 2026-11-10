#[path = "common/types.rs"]
mod types;


use core_config::parse::parse_document;
use std::fs;
use synthetic_checks::load::load_checks;
use synthetic_checks::model::{
    certificate_day_value, failure_run_len, CertificateDay, CheckFile, CheckKind, DEFAULT_CERT_DAYS, DEFAULT_CONSECUTIVE_FAILURES,
    DEFAULT_INTERVAL_SECONDS, DEFAULT_MIN_FAILING_LOCATIONS, DEFAULT_TIMEOUT_SECONDS, MAX_CHECKS, MAX_NAME_LEN, MAX_SCOPE_ENTRIES,
};
use tempfile::tempdir;
use types::TestResult;


const FILE_NAME: &str = "checks.yaml";


const KIND_COUNT: usize = 5;


const CERT_LONG: u64 = 60;


const CERT_SHORT: u64 = 10;


const MINIMAL: &str = "checks:\n  - name: web\n    kind: http\n    target: https://example.org/\n    locations: [paris]\n";


const FULL: &str = "scope: [10.1.0.0/24]\nchecks:\n  - name: db\n    kind: tcp\n    target: db.example.org:5432\n    interval_seconds: 30\n    timeout_seconds: 5\n    consecutive_failures: 2\n    locations: [paris, berlin]\n    min_failing_locations: 2\n    certificate_days: [60, 10]\n";


fn parse(text: &str) -> Result<CheckFile, core_config::error::ConfigError> {
    parse_document(text, FILE_NAME)
}


fn check_with(line: &str) -> String {
    format!("checks:\n  - name: web\n    kind: dns\n    target: example.org\n    locations: [paris]\n{line}\n")
}


fn day_values(days: &[CertificateDay]) -> Vec<u64> {
    days.iter().map(|day| certificate_day_value(*day)).collect()
}


fn message_of(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(parse(text).err().ok_or("expected an error")?.to_string())
}


#[test]
fn defaults_apply() -> TestResult {
    let file = parse(MINIMAL)?;
    let check = file.checks.first().ok_or("no check")?;
    assert_eq!(check.kind, CheckKind::Http);
    assert_eq!(check.interval_seconds, DEFAULT_INTERVAL_SECONDS);
    assert_eq!(check.timeout_seconds, DEFAULT_TIMEOUT_SECONDS);
    assert_eq!(failure_run_len(check.consecutive_failures), DEFAULT_CONSECUTIVE_FAILURES as usize);
    assert_eq!(check.min_failing_locations, DEFAULT_MIN_FAILING_LOCATIONS);
    assert_eq!(day_values(&check.certificate_days), DEFAULT_CERT_DAYS.to_vec());
    assert!(file.scope.is_empty());
    Ok(())
}


#[test]
fn full_entry_and_scope_parse() -> TestResult {
    let file = parse(FULL)?;
    let check = file.checks.first().ok_or("no check")?;
    assert_eq!(check.kind, CheckKind::Tcp);
    assert_eq!(check.locations, vec!["paris", "berlin"]);
    assert_eq!(day_values(&check.certificate_days), vec![CERT_LONG, CERT_SHORT]);
    assert_eq!(file.scope.len(), 1);
    Ok(())
}


#[test]
fn every_kind_parses() -> TestResult {
    let text = "checks:\n".to_string()
        + &["http", "tcp", "icmp", "dns", "tls"]
            .iter()
            .map(|kind| format!("  - name: {kind}\n    kind: {kind}\n    target: example.org\n    locations: [paris]\n"))
            .collect::<String>();
    assert_eq!(parse(&text)?.checks.len(), KIND_COUNT);
    Ok(())
}


#[test]
fn limit_errors_name_file_and_line() -> TestResult {
    let message = message_of(&check_with("    interval_seconds: 1"))?;
    assert!(message.starts_with(FILE_NAME), "{message}");
    assert!(message.contains("`interval_seconds` must be between"), "{message}");
    assert!(message.starts_with("checks.yaml:2:"), "{message}");
    Ok(())
}


#[test]
fn each_limit_is_enforced() -> TestResult {
    let cases = [
        ("    timeout_seconds: 0", "`timeout_seconds` must be between"),
        ("    interval_seconds: 20\n    timeout_seconds: 30", "must not exceed"),
        ("    consecutive_failures: 0", "`consecutive_failures` must be between"),
        ("    min_failing_locations: 2", "`min_failing_locations` must be between"),
        ("    certificate_days: []", "`certificate_days` must be between"),
        ("    certificate_days: [0]", "`certificate_days` must be between"),
        ("    bogus: 1", "unknown field"),
    ];
    cases.iter().try_for_each(|(line, expected)| -> TestResult {
        let message = message_of(&check_with(line))?;
        assert!(message.contains(expected), "{line}: {message}");
        Ok(())
    })
}


#[test]
fn text_limits_are_enforced() -> TestResult {
    let long_name = "n".repeat(MAX_NAME_LEN + 1);
    let cases = [
        "checks:\n  - name: \"\"\n    kind: dns\n    target: x\n    locations: [a]\n".to_string(),
        format!("checks:\n  - name: {long_name}\n    kind: dns\n    target: x\n    locations: [a]\n"),
        "checks:\n  - name: \"a\\nb\"\n    kind: dns\n    target: x\n    locations: [a]\n".to_string(),
        "checks:\n  - name: a\n    kind: dns\n    target: x\n    locations: [\"\"]\n".to_string(),
        "checks:\n  - name: a\n    kind: dns\n    target: x\n    locations: []\n".to_string(),
    ];
    cases.iter().try_for_each(|text| -> TestResult {
        assert!(message_of(text)?.contains("must be"), "{text}");
        Ok(())
    })
}


#[test]
fn duplicates_are_refused() -> TestResult {
    let locations = "checks:\n  - name: a\n    kind: dns\n    target: x\n    locations: [p, p]\n";
    assert!(message_of(locations)?.contains("duplicate entry"));
    let names = format!("{MINIMAL}{}", MINIMAL.trim_start_matches("checks:\n"));
    assert!(message_of(&names)?.contains("duplicate entry"));
    Ok(())
}


#[test]
fn error_text_never_echoes_the_input_value() -> TestResult {
    let duplicate = "checks:\n  - name: a\n    kind: dns\n    target: x\n    locations: [MARKERDUP, MARKERDUP]\n";
    let range = check_with("    interval_seconds: 987654321");
    let timeout = check_with("    interval_seconds: 20\n    timeout_seconds: 29");
    let cases = [
        (duplicate.to_string(), "MARKERDUP", "locations"),
        (range, "987654321", "interval_seconds"),
        (timeout, "29", "timeout_seconds"),
    ];
    cases.iter().try_for_each(|(text, marker, field)| -> TestResult {
        let message = message_of(text)?;
        assert!(message.contains(field), "{message}");
        assert!(!message.contains(marker), "{message}");
        Ok(())
    })
}


#[test]
fn file_counts_are_bounded() -> TestResult {
    let scope = format!("scope: [{}]\nchecks: []\n", vec!["10.0.0.0/8"; MAX_SCOPE_ENTRIES + 1].join(","));
    assert!(message_of(&scope)?.contains("`scope` must be between"));
    let checks = format!(
        "checks: [{}]\n",
        vec!["{name: a, kind: dns, target: x, locations: [p]}"; MAX_CHECKS + 1].join(",")
    );
    assert!(message_of(&checks)?.contains("`checks` must be between"));
    Ok(())
}


#[test]
fn load_checks_reads_a_file_and_reports_missing() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join(FILE_NAME);
    fs::write(&path, MINIMAL)?;
    assert_eq!(load_checks(&path)?.checks.len(), 1);
    assert!(load_checks(&dir.path().join("absent.yaml")).is_err());
    Ok(())
}


#[test]
fn a_ca_file_is_kept_and_bounded() -> TestResult {
    assert_eq!(parse(MINIMAL)?.ca_file, None);
    let kept = parse(&format!("ca_file: /etc/ostyr/ca.pem\n{MINIMAL}"))?;
    assert_eq!(kept.ca_file.as_deref(), Some("/etc/ostyr/ca.pem"));
    assert!(message_of(&format!("ca_file: \"\"\n{MINIMAL}"))?.contains("ca_file"));
    Ok(())
}
