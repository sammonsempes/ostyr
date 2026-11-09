use crate::support::{connection, mapping, process, TEST_PID};
use crate::types::TestResult;
use serde_json::{json, Value};
use sigma_sql::error::SigmaError;
use stream_correlation::base::{base_matches, compile_base};
use stream_correlation::check::{dash_variants, string_pattern};
use stream_correlation::error::{redacted, CorrelationError};
use stream_correlation::field::{event_time_ms, field_texts, group_key, lookup};


const DASH_VARIANT_COUNT: usize = 5;


const GROUP_PARTS: usize = 2;


const FRACTION_MS: i64 = 1250;


const HUGE_PATTERN: usize = 200_000;


fn rule_text(category: &str, product: &str, detection: &str) -> String {
    format!("title: Test rule\nlogsource:\n  category: {category}\n{product}detection:\n{detection}")
}


fn process_rule(detection: &str) -> String {
    rule_text("process_creation", "", detection)
}


fn matches_event(text: &str, event: &Value) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(base_matches(&compile_base(text, None, &mapping()?)?, event))
}


fn curl_event() -> Value {
    process(1, "e1", "h1", "/usr/bin/curl", "curl -s HTTP://x/y.sh")
}


fn refused(text: &str) -> Result<CorrelationError, Box<dyn std::error::Error>> {
    match compile_base(text, None, &mapping()?) {
        Ok(_) => Err("the rule was accepted".into()),
        Err(error) => Ok(error),
    }
}


fn sigma_error(text: &str) -> Result<SigmaError, Box<dyn std::error::Error>> {
    match refused(text)? {
        CorrelationError::Sigma(error) => Ok(error),
        other => Err(format!("not a Sigma error: {other}").into()),
    }
}


#[test]
fn equality_is_exact_case_insensitive_and_honours_wildcards() -> TestResult {
    let event = curl_event();
    assert!(matches_event(
        &process_rule("  selection:\n    Image: /USR/bin/CURL\n  condition: selection\n"),
        &event
    )?);
    assert!(matches_event(
        &process_rule("  selection:\n    Image: /usr/bin/c*\n  condition: selection\n"),
        &event
    )?);
    assert!(matches_event(
        &process_rule("  selection:\n    Image: /usr/bin/cur?\n  condition: selection\n"),
        &event
    )?);
    assert!(!matches_event(
        &process_rule("  selection:\n    Image: /usr/bin\n  condition: selection\n"),
        &event
    )?);
    Ok(())
}


#[test]
fn string_modifiers_anchor_as_documented() -> TestResult {
    let event = curl_event();
    let hit = |key: &str, value: &str| {
        matches_event(
            &process_rule(&format!("  selection:\n    {key}: '{value}'\n  condition: selection\n")),
            &event,
        )
    };
    assert!(hit("CommandLine|contains", "http://X")?);
    assert!(!hit("CommandLine|contains", "wget")?);
    assert!(hit("CommandLine|startswith", "CURL -s")?);
    assert!(!hit("CommandLine|startswith", "-s")?);
    assert!(hit("CommandLine|endswith", "Y.SH")?);
    assert!(!hit("CommandLine|endswith", "curl")?);
    Ok(())
}


#[test]
fn regex_is_case_sensitive() -> TestResult {
    let event = curl_event();
    assert!(matches_event(
        &process_rule("  selection:\n    CommandLine|re: 'curl\\s-s'\n  condition: selection\n"),
        &event
    )?);
    assert!(!matches_event(
        &process_rule("  selection:\n    CommandLine|re: 'CURL'\n  condition: selection\n"),
        &event
    )?);
    Ok(())
}


#[test]
fn cidr_matches_addresses_only() -> TestResult {
    let rule = rule_text(
        "network_connection",
        "",
        "  selection:\n    DestinationIp|cidr:\n      - 10.0.0.0/8\n      - 2001:db8::/32\n  condition: selection\n",
    );
    assert!(matches_event(&rule, &connection(1, "e", "h", "10.1.2.3"))?);
    assert!(matches_event(&rule, &connection(1, "e", "h", "2001:db8::1"))?);
    assert!(!matches_event(&rule, &connection(1, "e", "h", "192.168.0.1"))?);
    assert!(!matches_event(&rule, &connection(1, "e", "h", "not-an-ip"))?);
    Ok(())
}


#[test]
fn exists_and_null_test_presence() -> TestResult {
    let event = curl_event();
    let exists = |flag: &str| {
        matches_event(
            &process_rule(&format!("  selection:\n    User|exists: {flag}\n  condition: selection\n")),
            &event,
        )
    };
    assert!(!exists("true")?);
    assert!(exists("false")?);
    assert!(matches_event(
        &process_rule("  selection:\n    User: null\n  condition: selection\n"),
        &event
    )?);
    assert!(!matches_event(
        &process_rule("  selection:\n    Image: null\n  condition: selection\n"),
        &event
    )?);
    Ok(())
}


#[test]
fn numbers_and_booleans_compare_as_text() -> TestResult {
    let event = curl_event();
    let pid = TEST_PID.to_string();
    let rule = |key: &str, value: &str| process_rule(&format!("  selection:\n    {key}: {value}\n  condition: selection\n"));
    assert!(matches_event(&rule("ProcessId", &pid), &event)?);
    assert!(!matches_event(&rule("ProcessId", "1"), &event)?);
    assert!(matches_event(&rule("ProcessId|startswith", "42"), &event)?);
    let flagged = json!({"@timestamp": "2026-11-04T10:00:00Z", "event": {"category": ["network"]}, "network": {"direction": true}});
    assert!(matches_event(
        &rule_text("network_connection", "", "  selection:\n    Initiated: true\n  condition: selection\n"),
        &flagged
    )?);
    Ok(())
}


#[test]
fn windash_matches_every_dash_variant() -> TestResult {
    let rule = process_rule("  selection:\n    CommandLine|windash|contains: ' -enc'\n  condition: selection\n");
    assert!(matches_event(&rule, &process(1, "e", "h", "/x", "powershell -enc AAA"))?);
    assert!(matches_event(&rule, &process(1, "e", "h", "/x", "powershell /enc AAA"))?);
    assert!(matches_event(&rule, &process(1, "e", "h", "/x", "powershell \u{2013}enc AAA"))?);
    assert!(!matches_event(&rule, &process(1, "e", "h", "/x", "powershell enc AAA"))?);
    assert_eq!(dash_variants("a-b").len(), DASH_VARIANT_COUNT);
    Ok(())
}


#[test]
fn all_modifier_needs_every_value() -> TestResult {
    let event = curl_event();
    let rule = |values: &str| process_rule(&format!("  selection:\n    CommandLine|contains|all:\n{values}  condition: selection\n"));
    assert!(matches_event(&rule("      - curl\n      - '-s'\n"), &event)?);
    assert!(!matches_event(&rule("      - curl\n      - nothere\n"), &event)?);
    Ok(())
}


#[test]
fn lists_are_alternatives_and_maps_are_conjunctions() -> TestResult {
    let event = curl_event();
    let any_value = process_rule("  selection:\n    Image|endswith:\n      - /wget\n      - /curl\n  condition: selection\n");
    assert!(matches_event(&any_value, &event)?);
    let any_map = process_rule("  selection:\n    - Image|endswith: /wget\n    - Image|endswith: /curl\n  condition: selection\n");
    assert!(matches_event(&any_map, &event)?);
    let both = process_rule("  selection:\n    Image|endswith: /curl\n    CommandLine|contains: nothere\n  condition: selection\n");
    assert!(!matches_event(&both, &event)?);
    Ok(())
}


#[test]
fn condition_forms_are_evaluated() -> TestResult {
    let event = curl_event();
    let detection = |condition: &str| {
        process_rule(&format!(
            "  sel_curl:\n    Image|endswith: /curl\n  sel_wget:\n    Image|endswith: /wget\n  filter_x:\n    CommandLine|contains: nothere\n  condition: {condition}\n"
        ))
    };
    assert!(matches_event(&detection("sel_curl and not filter_x"), &event)?);
    assert!(!matches_event(&detection("sel_curl and filter_x"), &event)?);
    assert!(matches_event(&detection("sel_wget or sel_curl"), &event)?);
    assert!(matches_event(&detection("sel_curl or sel_wget"), &event)?);
    assert!(!matches_event(&detection("sel_wget and sel_curl"), &event)?);
    assert!(!matches_event(&detection("sel_wget or filter_x"), &event)?);
    assert!(matches_event(&detection("1 of sel_*"), &event)?);
    assert!(!matches_event(&detection("all of sel_*"), &event)?);
    assert!(!matches_event(&detection("all of them"), &event)?);
    assert!(matches_event(
        &detection("(sel_wget or sel_curl) and not (filter_x or sel_wget)"),
        &event
    )?);
    assert!(matches_event(&detection("not sel_wget and not filter_x"), &event)?);
    Ok(())
}


#[test]
fn logsource_filters_events() -> TestResult {
    let rule = rule_text(
        "process_creation",
        "  product: linux\n",
        "  selection:\n    Image|endswith: /curl\n  condition: selection\n",
    );
    assert!(matches_event(&rule, &curl_event())?);
    assert!(!matches_event(&rule, &connection(1, "e", "h", "10.0.0.1"))?);
    let windows = json!({
        "@timestamp": "2026-11-04T10:00:00Z",
        "event": {"category": "process"},
        "host": {"os": {"type": "windows"}},
        "process": {"executable": "/x/curl"},
    });
    assert!(!matches_event(&rule, &windows)?);
    let no_os = json!({"@timestamp": "2026-11-04T10:00:00Z", "event": {"category": "process"}, "process": {"executable": "/x/curl"}});
    assert!(!matches_event(&rule, &no_os)?);
    let any_os = process_rule("  selection:\n    Image|endswith: /curl\n  condition: selection\n");
    assert!(matches_event(&any_os, &no_os)?);
    Ok(())
}


#[test]
fn flat_dotted_keys_are_read_too() -> TestResult {
    let flat = json!({"event.category": ["process"], "process.executable": "/usr/bin/curl", "gone": null});
    assert!(matches_event(
        &process_rule("  selection:\n    Image|endswith: /curl\n  condition: selection\n"),
        &flat
    )?);
    assert!(lookup(&flat, "gone").is_none());
    Ok(())
}


#[test]
fn field_helpers_cover_arrays_objects_and_keys() -> TestResult {
    let event = json!({"a": {"list": ["x", 1, true, {"deep": 1}], "map": {"k": 1}}, "host": {"name": "h"}, "user": {"name": "u"}});
    assert_eq!(
        field_texts(&event, "a.list"),
        Some(vec!["x".to_string(), "1".to_string(), "true".to_string()])
    );
    assert_eq!(field_texts(&event, "a.map"), Some(Vec::new()));
    assert!(field_texts(&event, "a.none").is_none());
    let fields = vec!["host.name".to_string(), "user.name".to_string()];
    assert_eq!(group_key(&event, &fields).map(|key| key.split('\u{1f}').count()), Some(GROUP_PARTS));
    assert!(group_key(&event, &["missing".to_string()]).is_none());
    assert_eq!(group_key(&event, &[]), Some(String::new()));
    Ok(())
}


#[test]
fn event_time_reports_each_defect() -> TestResult {
    assert!(matches!(event_time_ms(&json!({})), Err(CorrelationError::MissingTimestamp)));
    assert!(matches!(
        event_time_ms(&json!({"@timestamp": 1})),
        Err(CorrelationError::MissingTimestamp)
    ));
    assert!(matches!(
        event_time_ms(&json!({"@timestamp": "yesterday"})),
        Err(CorrelationError::BadTimestamp { .. })
    ));
    let first = event_time_ms(&json!({"@timestamp": "2026-11-04T10:00:00.000Z"}))?;
    let second = event_time_ms(&json!({"@timestamp": "2026-11-04T10:00:01.250Z"}))?;
    assert_eq!(second - first, FRACTION_MS);
    Ok(())
}


#[test]
fn unsupported_and_invalid_rules_are_typed_errors() -> TestResult {
    let ok_detection = "  selection:\n    Image: /x\n  condition: selection\n";
    assert!(matches!(
        sigma_error(&rule_text("process_creation", "  service: sshd\n", ok_detection))?,
        SigmaError::Unsupported { .. }
    ));
    assert!(matches!(
        sigma_error(&format!("title: T\nlogsource:\n  product: linux\ndetection:\n{ok_detection}"))?,
        SigmaError::Unsupported { .. }
    ));
    assert!(matches!(
        sigma_error(&rule_text("unknown_category", "", ok_detection))?,
        SigmaError::Unsupported { .. }
    ));
    assert!(matches!(
        sigma_error(&rule_text("process_creation", "  product: beos\n", ok_detection))?,
        SigmaError::Unsupported { .. }
    ));
    let failing = |selection: &str| sigma_error(&process_rule(&format!("  selection:\n{selection}  condition: selection\n")));
    assert!(matches!(failing("    Nope: x\n")?, SigmaError::UnmappedField { .. }));
    assert!(matches!(failing("    - keyword\n")?, SigmaError::Unsupported { .. }));
    assert!(matches!(failing("    keyword\n")?, SigmaError::Unsupported { .. }));
    assert!(matches!(failing("    {}\n")?, SigmaError::Unsupported { .. }));
    assert!(matches!(failing("    []\n")?, SigmaError::Unsupported { .. }));
    assert!(matches!(failing("    Image: []\n")?, SigmaError::Unsupported { .. }));
    assert!(matches!(failing("    Image|re: '('\n")?, SigmaError::BadValue { .. }));
    let bad_cidr = rule_text(
        "network_connection",
        "",
        "  selection:\n    DestinationIp|cidr: 10.0.0.0\n  condition: selection\n",
    );
    assert!(matches!(sigma_error(&bad_cidr)?, SigmaError::BadValue { .. }));
    assert!(matches!(failing("    Image|exists: maybe\n")?, SigmaError::BadValue { .. }));
    assert!(matches!(failing("    Image|contains: true\n")?, SigmaError::BadValue { .. }));
    assert!(matches!(failing("    Image: [[a]]\n")?, SigmaError::BadValue { .. }));
    assert!(matches!(failing("    Image|base64: a\n")?, SigmaError::UnknownModifier { .. }));
    let huge = "?".repeat(HUGE_PATTERN);
    assert!(matches!(
        failing(&format!("    Image|contains: '{huge}'\n"))?,
        SigmaError::BadValue { .. }
    ));
    assert!(matches!(
        sigma_error(&process_rule("  selection:\n    Image: /x\n  condition: other\n"))?,
        SigmaError::MissingSelection { .. }
    ));
    assert!(matches!(refused("not: a rule")?, CorrelationError::Config(_)));
    Ok(())
}


#[test]
fn string_patterns_escape_regex_syntax() -> TestResult {
    assert_eq!(string_pattern(sigma_sql::modifier::Matcher::Equals, "a.b*"), "^a\\.b.*$");
    assert_eq!(string_pattern(sigma_sql::modifier::Matcher::Contains, "a?"), "a.");
    Ok(())
}


#[test]
fn other_sigma_errors_pass_through_redaction_unchanged() -> TestResult {
    let error = redacted(SigmaError::Usage);
    assert!(matches!(error, CorrelationError::Sigma(SigmaError::Usage)));
    let fixed = redacted(SigmaError::Unsupported {
        rule: "r".to_string(),
        construct: "c".to_string(),
    });
    assert!(matches!(fixed, CorrelationError::Sigma(SigmaError::Unsupported { .. })));
    Ok(())
}


#[test]
fn identifier_errors_hide_the_identifier() -> TestResult {
    let error = redacted(SigmaError::BadIdentifier("/srv/canary-9".to_string()));
    assert!(!error.to_string().contains("canary-9"), "{error}");
    Ok(())
}


#[test]
fn constructs_naming_a_key_become_their_fixed_class() -> TestResult {
    let error = redacted(SigmaError::Unsupported {
        rule: "r".to_string(),
        construct: "top-level key /srv/canary-9".to_string(),
    });
    assert!(error.to_string().ends_with("unsupported construct top-level key"), "{error}");
    Ok(())
}
