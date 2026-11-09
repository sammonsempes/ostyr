#[path = "common/types.rs"]
mod types;


use compliance::error::ComplianceError;
use compliance::load::{
    load_baseline, load_exceptions, parse_baseline, parse_exceptions, MAX_CONTROLS, MAX_EXCEPTIONS, MAX_FILE_BYTES, MAX_FRAMEWORKS, MAX_ID_LEN,
    MAX_QUERY_LEN, MAX_TEXT_LEN,
};
use compliance::model::{Baseline, Exception, Expectation, Framework, Scope, Severity};
use core_config::error::ConfigError;
use std::io::Read;
use types::TestResult;


const VALID: &str = "version: 1
tenant: acme
name: linux-hardening
actions:
  - lock-account
controls:
  - id: ssh-root
    query: SELECT value FROM augeas WHERE path = '/files/etc/ssh/sshd_config/PermitRootLogin'
    expect:
      column_equals:
        column: value
        value: 'no'
    severity: high
    frameworks:
      - framework: anssi
        reference: R28
      - framework: disa_stig
        reference: V-238218
  - id: no-uid0
    query: SELECT username FROM users WHERE uid = 0 AND username != 'root'
    expect:
      row_count: 0
    severity: critical
    correction:
      action: lock-account
  - id: banner
    query: SELECT value FROM augeas
    expect:
      column_matches:
        column: value
        pattern: '^Authorized'
    severity: low
";


const VALID_EXCEPTIONS: &str = "exceptions:
  - control: ssh-root
    scope:
      device: web1
    owner: alice
    reason: legacy application
    expires: 2026-12-01T00:00:00Z
  - control: banner
    scope:
      tag: lab
    owner: bob
    reason: lab hosts
    expires: 2027-01-01T00:00:00Z
";


const CONTROL_COUNT: usize = 3;


const EXCEPTION_COUNT: usize = 2;


const EXPIRY_TIMESTAMP: i64 = 1_796_083_200;


const EXTRA: usize = 1;


const LAST_CONTROL: usize = 2;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("device gone"))
    }
}


fn baseline_with(control_fields: &str) -> String {
    format!("version: 1\ntenant: acme\nname: base\nactions: [fix]\ncontrols:\n  - id: c1\n    query: SELECT 1\n    severity: low\n{control_fields}")
}


fn baseline_error(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    match parse_baseline(&mut text.as_bytes(), "base.yaml") {
        Ok(_) => Err("expected a refusal".into()),
        Err(error) => Ok(error.to_string()),
    }
}


fn exceptions_error(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    match parse_exceptions(&mut text.as_bytes(), "exc.yaml") {
        Ok(_) => Err("expected a refusal".into()),
        Err(error) => Ok(error.to_string()),
    }
}


fn exception_text(owner_line: &str, scope: &str, reason: &str) -> String {
    format!("exceptions:\n  - control: c1\n    scope:\n      {scope}\n{owner_line}    reason: {reason}\n    expires: 2026-12-01T00:00:00Z\n")
}


#[test]
fn valid_baseline_loads_with_every_expectation_kind() -> TestResult {
    let baseline = parse_baseline(&mut VALID.as_bytes(), "base.yaml")?;
    assert_eq!(baseline.controls.len(), CONTROL_COUNT);
    let kinds: Vec<&Expectation> = baseline.controls.iter().map(|control| &control.expect).collect();
    assert!(matches!(kinds.first(), Some(Expectation::ColumnEquals { .. })));
    assert!(matches!(kinds.get(1), Some(Expectation::RowCount(0))));
    assert!(matches!(kinds.get(LAST_CONTROL), Some(Expectation::ColumnMatches { .. })));
    Ok(())
}


#[test]
fn framework_mapping_round_trips() -> TestResult {
    let baseline = parse_baseline(&mut VALID.as_bytes(), "base.yaml")?;
    let first = baseline.controls.first().ok_or("missing control")?;
    assert_eq!(first.severity, Severity::High);
    assert_eq!(first.frameworks.first().map(|reference| reference.framework), Some(Framework::Anssi));
    assert_eq!(first.frameworks.get(1).map(|reference| reference.framework), Some(Framework::DisaStig));
    let text = serde_json::to_string(&baseline)?;
    let again: Baseline = serde_json::from_str(&text)?;
    assert_eq!(again, baseline);
    Ok(())
}


#[test]
fn correction_is_off_by_default() -> TestResult {
    let baseline = parse_baseline(&mut VALID.as_bytes(), "base.yaml")?;
    let correction = baseline
        .controls
        .get(1)
        .and_then(|control| control.correction.as_ref())
        .ok_or("missing correction")?;
    assert_eq!(correction.action, "lock-account");
    assert!(!correction.enabled);
    assert!(baseline.controls.first().ok_or("missing")?.correction.is_none());
    Ok(())
}


#[test]
fn syntax_error_names_file_and_line() -> TestResult {
    let message = baseline_error("version: 1\nname: [\n")?;
    assert!(message.starts_with("base.yaml:"), "{message}");
    Ok(())
}


#[test]
fn unknown_field_is_refused() -> TestResult {
    let message = baseline_error(&baseline_with("    expect:\n      row_count: 0\n    surprise: 1\n"))?;
    assert!(message.contains("surprise"), "{message}");
    Ok(())
}


#[test]
fn unsupported_version_is_refused() -> TestResult {
    let message = baseline_error("version: 2\ntenant: acme\nname: base\ncontrols: []\n")?;
    assert!(message.contains("unsupported baseline version 2"), "{message}");
    Ok(())
}


#[test]
fn empty_name_is_refused() -> TestResult {
    let message = baseline_error("version: 1\ntenant: acme\nname: ' '\ncontrols: []\n")?;
    assert!(message.contains("`name` is empty"), "{message}");
    Ok(())
}


#[test]
fn duplicate_control_id_is_refused() -> TestResult {
    let control = "  - id: c1\n    query: SELECT 1\n    severity: low\n    expect:\n      row_count: 0\n";
    let message = baseline_error(&format!(
        "version: 1\ntenant: acme\nname: base\nactions: [fix]\ncontrols:\n{control}{control}"
    ))?;
    assert!(message.contains("duplicate control id"), "{message}");
    Ok(())
}


#[test]
fn too_many_controls_is_refused() -> TestResult {
    let control = "  - id: cN\n    query: SELECT 1\n    severity: low\n    expect:\n      row_count: 0\n";
    let controls = control.repeat(MAX_CONTROLS + EXTRA);
    let message = baseline_error(&format!("version: 1\ntenant: acme\nname: base\nactions: [fix]\ncontrols:\n{controls}"))?;
    assert!(message.contains("more than"), "{message}");
    Ok(())
}


#[test]
fn control_limits_are_enforced() -> TestResult {
    let long_id = "x".repeat(MAX_ID_LEN + EXTRA);
    let long_query = "x".repeat(MAX_QUERY_LEN + EXTRA);
    let long_text = "x".repeat(MAX_TEXT_LEN + EXTRA);
    let cases = [
        format!("version: 1\ntenant: t\nname: b\ncontrols:\n  - id: {long_id}\n    query: q\n    severity: low\n    expect:\n      row_count: 0\n"),
        format!("version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: {long_query}\n    severity: low\n    expect:\n      row_count: 0\n"),
        "version: 1\ntenant: t\nname: b\ncontrols:\n  - id: ''\n    query: q\n    severity: low\n    expect:\n      row_count: 0\n".to_string(),
        format!("version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      column_equals:\n        column: a\n        value: {long_text}\n"),
        "version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      column_equals:\n        column: ''\n        value: v\n"
            .to_string(),
        format!("version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      column_matches:\n        column: a\n        pattern: {long_text}\n"),
        "version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      column_matches:\n        column: ''\n        pattern: p\n"
            .to_string(),
        "version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      column_matches:\n        column: a\n        pattern: ''\n"
            .to_string(),
        format!("version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      row_count: 0\n    correction:\n      action: {long_text}\n"),
        "version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      row_count: 0\n    correction:\n      action: ''\n"
            .to_string(),
        "version: 1\ntenant: t\nname: b\ncontrols:\n  - id: c\n    query: q\n    severity: low\n    expect:\n      row_count: 0\n    frameworks:\n      - framework: anssi\n        reference: ''\n"
            .to_string(),
    ];
    cases
        .iter()
        .try_for_each(|text| baseline_error(text).map(|message| assert!(message.contains("control `"), "{message}")))?;
    Ok(())
}


#[test]
fn invalid_pattern_is_refused() -> TestResult {
    let message = baseline_error(&baseline_with(
        "    expect:\n      column_matches:\n        column: a\n        pattern: '('\n",
    ))?;
    assert!(message.contains("invalid pattern"), "{message}");
    Ok(())
}


#[test]
fn too_many_framework_references_are_refused() -> TestResult {
    let reference = "      - framework: anssi\n        reference: R1\n";
    let references = reference.repeat(MAX_FRAMEWORKS + EXTRA);
    let message = baseline_error(&baseline_with(&format!("    expect:\n      row_count: 0\n    frameworks:\n{references}")))?;
    assert!(message.contains("framework references"), "{message}");
    Ok(())
}


#[test]
fn oversized_file_is_refused() -> TestResult {
    let big = "#".repeat(usize::try_from(MAX_FILE_BYTES)? + EXTRA);
    let message = baseline_error(&big)?;
    assert!(message.contains("larger than"), "{message}");
    Ok(())
}


#[test]
fn read_failure_is_reported() -> TestResult {
    let result = parse_baseline(&mut FailingReader, "base.yaml");
    assert!(matches!(result, Err(ComplianceError::Config(ConfigError::Io { .. }))));
    Ok(())
}


#[test]
fn files_load_from_disk_and_missing_file_is_reported() -> TestResult {
    let dir = tempfile::tempdir()?;
    let base_path = dir.path().join("base.yaml");
    let exceptions_path = dir.path().join("exceptions.yaml");
    std::fs::write(&base_path, VALID)?;
    std::fs::write(&exceptions_path, VALID_EXCEPTIONS)?;
    assert_eq!(load_baseline(&base_path)?.controls.len(), CONTROL_COUNT);
    assert_eq!(load_exceptions(&exceptions_path)?.len(), EXCEPTION_COUNT);
    let missing = dir.path().join("absent.yaml");
    assert!(matches!(load_baseline(&missing), Err(ComplianceError::Config(ConfigError::Io { .. }))));
    assert!(matches!(load_exceptions(&missing), Err(ComplianceError::Config(ConfigError::Io { .. }))));
    Ok(())
}


#[test]
fn valid_exceptions_load() -> TestResult {
    let exceptions: Vec<Exception> = parse_exceptions(&mut VALID_EXCEPTIONS.as_bytes(), "exc.yaml")?;
    let first = exceptions.first().ok_or("missing")?;
    assert_eq!(first.scope, Scope::Device("web1".to_string()));
    assert_eq!(first.expires.unix_timestamp(), EXPIRY_TIMESTAMP);
    assert_eq!(
        exceptions.get(1).map(|exception| exception.scope.clone()),
        Some(Scope::Tag("lab".to_string()))
    );
    Ok(())
}


#[test]
fn exception_without_owner_is_refused() -> TestResult {
    let message = exceptions_error(&exception_text("", "device: d", "why"))?;
    assert!(message.contains("owner"), "{message}");
    Ok(())
}


#[test]
fn exception_without_expiry_is_refused() -> TestResult {
    let message = exceptions_error("exceptions:\n  - control: c1\n    scope:\n      device: d\n    owner: a\n    reason: r\n")?;
    assert!(message.contains("expires"), "{message}");
    Ok(())
}


#[test]
fn exception_with_empty_fields_is_refused() -> TestResult {
    let long_id = "x".repeat(MAX_ID_LEN + EXTRA);
    let cases = [
        exception_text("    owner: ''\n", "device: d", "why"),
        exception_text("    owner: a\n", "device: d", "''"),
        exception_text("    owner: a\n", "tag: ''", "why"),
        exception_text("    owner: a\n", &format!("device: {long_id}"), "why"),
        exception_text("    owner: a\n", "device: d", "why").replace("control: c1", "control: ''"),
    ];
    cases
        .iter()
        .try_for_each(|text| exceptions_error(text).map(|message| assert!(message.contains("exception for"), "{message}")))?;
    Ok(())
}


#[test]
fn too_many_exceptions_are_refused() -> TestResult {
    let entry = "  - control: c1\n    scope:\n      device: d\n    owner: a\n    reason: r\n    expires: 2026-12-01T00:00:00Z\n";
    let message = exceptions_error(&format!("exceptions:\n{}", entry.repeat(MAX_EXCEPTIONS + EXTRA)))?;
    assert!(message.contains("more than"), "{message}");
    Ok(())
}
