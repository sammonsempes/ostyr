use device_control::error::PolicyError;
use device_control::limits::{MAX_POLICY_BYTES, MAX_REASON_CHARS, MAX_RULES, MAX_SERIAL_CHARS};
use device_control::model::{Action, Mode, Policy};
use device_control::parse::{load_policy, parse_policy};
use std::error::Error;
use std::io::Read;
use std::path::Path;


fn parse(text: &str) -> Result<Policy, PolicyError> {
    parse_policy(&mut text.as_bytes(), "policy.yaml")
}


fn rule_with(field: &str) -> String {
    format!("default: allow\nrules:\n  - {{action: allow, {field}}}\n")
}


fn exception_with(rest: &str) -> String {
    format!("default: allow\nexceptions:\n  - rule: {{action: allow, class: \"08\"}}\n    owner: bob\n{rest}")
}


const FIXTURE_RULES: usize = 4;


const FIXTURE_EXCEPTIONS: usize = 2;


const ALIAS_COUNT: usize = 100_000;


const GOOD_EXCEPTION_TAIL: &str = "    expires: 2099-01-01T00:00:00Z\n    reason: ok\n";


#[test]
fn mode_absent_means_audit() -> Result<(), Box<dyn Error>> {
    let policy = parse("default: allow\n")?;
    assert_eq!(policy.mode, Mode::Audit);
    assert_eq!(policy.default, Action::Allow);
    assert!(policy.rules.is_empty());
    assert!(policy.exceptions.is_empty());
    Ok(())
}


#[test]
fn enforce_mode_and_a_full_rule_parse() -> Result<(), Box<dyn Error>> {
    let policy = parse(
        "mode: enforce\ndefault: block\nrules:\n  - {action: allow, class: \"03\", vendor: \"046d\", product: \"c52b\", serial: \"AB-1.2:3\"}\n",
    )?;
    assert_eq!(policy.mode, Mode::Enforce);
    assert_eq!(policy.rules.len(), 1);
    Ok(())
}


#[test]
fn a_good_exception_parses() -> Result<(), Box<dyn Error>> {
    let policy = parse(&exception_with(GOOD_EXCEPTION_TAIL))?;
    assert_eq!(policy.exceptions.len(), 1);
    Ok(())
}


#[test]
fn the_fixture_loads_from_a_path() -> Result<(), Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy.yaml");
    let policy = load_policy(&path)?;
    assert_eq!(policy.rules.len(), FIXTURE_RULES);
    assert_eq!(policy.exceptions.len(), FIXTURE_EXCEPTIONS);
    Ok(())
}


#[test]
fn a_missing_file_is_an_open_error() -> Result<(), Box<dyn Error>> {
    let result = load_policy(Path::new("/nonexistent/usb-policy.yaml"));
    assert!(matches!(result, Err(PolicyError::Open { .. })));
    Ok(())
}


#[test]
fn refused_documents() -> Result<(), Box<dyn Error>> {
    let long_reason = format!("    expires: 2099-01-01T00:00:00Z\n    reason: {}\n", "a".repeat(MAX_REASON_CHARS + 1));
    let cases = [
        "default: allow\nsurprise: 1\n".to_string(),
        "mode: observe\ndefault: allow\n".to_string(),
        "mode: enforce\n".to_string(),
        "default: allow\nrules:\n  - {action: block}\n".to_string(),
        rule_with("serial: \"AB\""),
        "default: allow\nrules:\n  - {action: block, class: \"08\", serial: \"AB\"}\n".to_string(),
        rule_with("class: \"8\""),
        rule_with("class: \"0A\""),
        rule_with("vendor: \"046D\""),
        rule_with("vendor: \"046\""),
        rule_with("vendor: \"046d0\""),
        rule_with("product: \"-123\""),
        rule_with("vendor: \"046d\", serial: \"-AB\""),
        rule_with("vendor: \"046d\", serial: \"a\\u202eb\""),
        rule_with("vendor: \"046d\", serial: \"a\\u200bb\""),
        rule_with("vendor: \"046d\", serial: 'a\"b'"),
        rule_with("vendor: \"046d\", serial: 'a\\b'"),
        rule_with("vendor: \"046d\", serial: \"a\\nallow\""),
        rule_with("vendor: \"046d\", serial: \"\""),
        rule_with(&format!("vendor: \"046d\", serial: \"{}\"", "a".repeat(MAX_SERIAL_CHARS + 1))),
        rule_with("vendor: \"046d\", color: red"),
        exception_with("    reason: ok\n"),
        exception_with("    expires: tomorrow\n    reason: ok\n"),
        exception_with("    expires: 2099-01-01T00:00:00Z\n"),
        exception_with("    expires: 2099-01-01T00:00:00Z\n    reason: ok\n    extra: 1\n"),
        exception_with(&long_reason),
        exception_with("    expires: 2099-01-01T00:00:00Z\n    reason: \"a\\u202eb\"\n"),
        exception_with("    expires: 2099-01-01T00:00:00Z\n    reason: \"a\\u200bb\"\n"),
        exception_with("    expires: 2099-01-01T00:00:00Z\n    reason: \"a\\nb\"\n"),
        exception_with("    expires: 2099-01-01T00:00:00Z\n    reason: 'a\"b'\n"),
        exception_with("    expires: 2099-01-01T00:00:00Z\n    reason: 'a\\b'\n"),
        "default: allow\nexceptions:\n  - rule: {action: allow, class: \"08\"}\n    owner: -bob\n    expires: 2099-01-01T00:00:00Z\n    reason: ok\n"
            .to_string(),
        "default: allow\nexceptions:\n  - rule: {action: allow}\n    owner: bob\n    expires: 2099-01-01T00:00:00Z\n    reason: ok\n".to_string(),
    ];
    cases.iter().for_each(|text| {
        assert!(matches!(parse(text), Err(PolicyError::Config(_))), "accepted: {text}");
    });
    Ok(())
}


#[test]
fn a_reason_of_exactly_the_cap_is_accepted() -> Result<(), Box<dyn Error>> {
    let tail = format!("    expires: 2099-01-01T00:00:00Z\n    reason: {}\n", "a".repeat(MAX_REASON_CHARS));
    parse(&exception_with(&tail))?;
    Ok(())
}


fn rules_document(count: usize) -> String {
    let rules = "  - {action: block, class: \"08\"}\n".repeat(count);
    format!("default: allow\nrules:\n{rules}")
}


#[test]
fn the_rule_count_is_capped_at_the_boundary() -> Result<(), Box<dyn Error>> {
    let accepted = parse(&rules_document(MAX_RULES))?;
    assert_eq!(accepted.rules.len(), MAX_RULES);
    let refused = parse(&rules_document(MAX_RULES + 1));
    assert!(matches!(refused, Err(PolicyError::TooManyRules { count, .. }) if count == MAX_RULES + 1));
    Ok(())
}


#[test]
fn exceptions_count_toward_the_cap() -> Result<(), Box<dyn Error>> {
    let exceptions = format!("  - rule: {{action: allow, class: \"08\"}}\n    owner: bob\n{GOOD_EXCEPTION_TAIL}");
    let text = format!("{}exceptions:\n{exceptions}", rules_document(MAX_RULES));
    assert!(matches!(parse(&text), Err(PolicyError::TooManyRules { .. })));
    Ok(())
}


#[test]
fn the_file_size_is_capped_at_the_boundary() -> Result<(), Box<dyn Error>> {
    let body = "default: allow\n";
    let padding = " ".repeat(usize::try_from(MAX_POLICY_BYTES)? - body.len());
    parse(&format!("{body}{padding}"))?;
    let refused = parse(&format!("{body}{padding} "));
    assert!(matches!(refused, Err(PolicyError::Config(_))));
    let endless = parse_policy(&mut std::io::repeat(b' '), "endless.yaml");
    assert!(matches!(endless, Err(PolicyError::Config(_))));
    Ok(())
}


#[test]
fn an_unreadable_source_is_an_error() -> Result<(), Box<dyn Error>> {
    let mut empty_then_invalid: &[u8] = b"\xff\xfe";
    let reader: &mut dyn Read = &mut empty_then_invalid;
    assert!(parse_policy(reader, "binary.yaml").is_err());
    Ok(())
}


#[test]
fn an_alias_flood_is_refused() -> Result<(), Box<dyn Error>> {
    let aliases = "  - *r\n".repeat(ALIAS_COUNT);
    let text = format!("default: allow\nrules:\n  - &r {{action: block, class: \"08\"}}\n{aliases}");
    assert!(parse(&text).is_err());
    Ok(())
}
