mod common;


use common::types::TestResult;
use core_config::error::ConfigError;
use metric_alerts::error::RuleError;
use metric_alerts::model::{Condition, Direction, Severity};
use metric_alerts::rules::{
    load_rules, parse_rules, validate_rule, MAX_DURATION_SECONDS, MAX_FILE_BYTES, MAX_ID_LEN, MAX_LABELS, MAX_LABEL_LEN, MAX_METRIC_LEN, MAX_RULES,
    MAX_RUNBOOK_LEN,
};
use std::io::{self, Read};


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }
}


const HOLD_FOR: u64 = 300;


const LOW_THRESHOLD: f64 = 5.0;


const LOW_CLEAR: f64 = 10.0;


const TWO_RULES: usize = 2;


const FILE: &str = "rules.yaml";


const THRESHOLD_LINE: u64 = 3;


pub fn rule(id: &str, condition: &str, extra: &str) -> String {
    format!(
        "  - id: {id}\n    metric: disk.used\n    condition: {condition}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n{extra}"
    )
}


pub fn file(rules: &[String]) -> String {
    format!("rules:\n{}", rules.concat())
}


pub fn parse(text: &str) -> Result<usize, RuleError> {
    parse_rules(&mut text.as_bytes(), FILE).map(|parsed| parsed.rules.len())
}


pub fn invalid_field(text: &str) -> Option<&'static str> {
    match parse(text) {
        Err(RuleError::Invalid { field, .. }) => Some(field),
        _ => None,
    }
}


const ABOVE: &str = "{kind: threshold, direction: above, threshold: 90}";


#[test]
fn full_rule_is_parsed() -> TestResult {
    let text = file(&[rule(
        "disk-high",
        "{kind: threshold, direction: below, threshold: 5, clear: 10}",
        "    for: 300\n    selector: {mount: /}\n    labels: {team: infra}\n",
    )]);
    let parsed = parse_rules(&mut text.as_bytes(), FILE)?;
    let first = parsed.rules.first().ok_or("no rule")?;
    assert_eq!(first.id, "disk-high");
    assert_eq!(first.hold_for, HOLD_FOR);
    assert_eq!(first.severity, Severity::High);
    assert_eq!(first.selector.get("mount").map(String::as_str), Some("/"));
    assert_eq!(
        first.condition,
        Condition::Threshold {
            direction: Direction::Below,
            threshold: LOW_THRESHOLD,
            clear: Some(LOW_CLEAR)
        }
    );
    Ok(())
}


#[test]
fn rate_and_absence_conditions_are_parsed() -> TestResult {
    let text = file(&[
        rule("a", "{kind: rate, direction: above, threshold: 2}", ""),
        rule("b", "{kind: absence, interval: 60}", ""),
    ]);
    assert_eq!(parse(&text)?, TWO_RULES);
    Ok(())
}


#[test]
fn parse_error_names_file_line_and_field() -> TestResult {
    let text = file(&[rule("a", "{kind: threshold, direction: sideways, threshold: 1}", "")]);
    match parse(&text) {
        Err(RuleError::Config(ConfigError::Parse { file, line, .. })) => {
            assert_eq!(file, FILE);
            assert_eq!(line, THRESHOLD_LINE + 1);
            Ok(())
        }
        other => Err(format!("unexpected: {other:?}").into()),
    }
}


#[test]
fn unknown_rule_field_is_refused() -> TestResult {
    let text = file(&[rule("a", ABOVE, "    colour: red\n")]);
    assert!(matches!(parse(&text), Err(RuleError::Config(_))));
    Ok(())
}


#[test]
fn read_failure_is_reported() -> TestResult {
    assert!(matches!(
        parse_rules(&mut FailingReader, FILE),
        Err(RuleError::Config(ConfigError::Io { .. }))
    ));
    Ok(())
}


#[test]
fn oversized_file_is_refused() -> TestResult {
    let padding = " ".repeat(MAX_FILE_BYTES as usize);
    let text = format!("{}{padding}", file(&[rule("a", ABOVE, "")]));
    assert!(matches!(parse(&text), Err(RuleError::FileTooLarge { .. })));
    Ok(())
}


#[test]
fn too_many_rules_are_refused() -> TestResult {
    let rules: Vec<String> = (0..=MAX_RULES).map(|index| rule(&format!("r{index}"), ABOVE, "")).collect();
    assert!(matches!(parse(&file(&rules)), Err(RuleError::TooManyRules { count, .. }) if count == MAX_RULES + 1));
    Ok(())
}


#[test]
fn duplicate_ids_are_refused() -> TestResult {
    let text = file(&[rule("a", ABOVE, ""), rule("a", ABOVE, "")]);
    assert!(matches!(parse(&text), Err(RuleError::DuplicateId { rule, .. }) if rule == "a"));
    Ok(())
}


#[test]
fn bounds_are_checked_per_field() -> TestResult {
    let long_label = "x".repeat(MAX_LABEL_LEN + 1);
    let many_labels = (0..=MAX_LABELS).map(|index| format!("l{index}: v")).collect::<Vec<_>>().join(", ");
    let cases = [
        (rule(&"x".repeat(MAX_ID_LEN + 1), ABOVE, ""), "id"),
        (rule("\"\"", ABOVE, ""), "id"),
        (rule("a", ABOVE, &format!("    selector: {{k: {long_label}}}\n")), "selector"),
        (rule("a", ABOVE, &format!("    selector: {{{long_label}: v}}\n")), "selector"),
        (rule("a", ABOVE, &format!("    labels: {{{many_labels}}}\n")), "labels"),
        (rule("a", ABOVE, &format!("    for: {}\n", MAX_DURATION_SECONDS + 1)), "for"),
        (
            rule("a", ABOVE, "").replace("close_after: 60", &format!("close_after: {}", MAX_DURATION_SECONDS + 1)),
            "close_after",
        ),
        (rule("a", ABOVE, "").replace("disk.used", &"m".repeat(MAX_METRIC_LEN + 1)), "metric"),
        (
            rule("a", ABOVE, "").replace("https://r.example.org", &"r".repeat(MAX_RUNBOOK_LEN + 1)),
            "runbook",
        ),
        (rule("a", "{kind: absence, interval: 0}", ""), "condition"),
        (
            rule("a", "{kind: threshold, direction: above, threshold: 90, clear: 95}", ""),
            "condition",
        ),
        (rule("a", "{kind: rate, direction: below, threshold: 1, clear: 0}", ""), "condition"),
    ];
    cases.iter().try_for_each(|(rule_text, field)| {
        let observed = invalid_field(&file(std::slice::from_ref(rule_text)));
        (observed == Some(*field)).then_some(()).ok_or_else(|| format!("{field}: {observed:?}"))
    })?;
    Ok(())
}


#[test]
fn invalid_error_names_the_rule() -> TestResult {
    let text = file(&[rule("bad", "{kind: absence, interval: 0}", "")]);
    let message = parse(&text).err().map(|error| error.to_string());
    assert_eq!(message.as_deref(), Some("rules.yaml: rule `bad`: invalid `condition`"));
    Ok(())
}


#[test]
fn rules_load_from_a_file() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("rules.yaml");
    std::fs::write(&path, file(&[rule("a", ABOVE, "")]))?;
    assert_eq!(load_rules(&path)?.rules.len(), 1);
    assert!(matches!(
        load_rules(&directory.path().join("missing.yaml")),
        Err(RuleError::Config(ConfigError::Io { .. }))
    ));
    Ok(())
}


#[test]
fn non_finite_levels_are_invalid() -> TestResult {
    let text = file(&[rule("a", ABOVE, "")]);
    let mut parsed = parse_rules(&mut text.as_bytes(), FILE)?;
    let first = parsed.rules.first_mut().ok_or("no rule")?;
    let conditions = [
        Condition::Threshold {
            direction: Direction::Above,
            threshold: f64::INFINITY,
            clear: None,
        },
        Condition::Threshold {
            direction: Direction::Above,
            threshold: LOW_THRESHOLD,
            clear: Some(f64::NAN),
        },
    ];
    conditions.into_iter().try_for_each(|condition| {
        first.condition = condition;
        validate_rule(FILE, first).err().map(|_| ()).ok_or("accepted")
    })?;
    Ok(())
}


#[test]
fn unknown_condition_field_is_refused() -> TestResult {
    let text = file(&[rule("a", "{kind: threshold, direction: above, threshold: 90, extra: 1}", "")]);
    assert!(matches!(parse(&text), Err(RuleError::Config(_))));
    Ok(())
}
