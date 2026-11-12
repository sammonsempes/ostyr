use crate::support::{bench, feed, mapping, stamp, MAPPING};
use crate::types::TestResult;
use serde_json::{json, Value};
use sigma_sql::compile::{compile_rule, SqlOptions};
use sigma_sql::error::SigmaError;
use sigma_sql::mapping::parse_mapping;
use stream_correlation::base::{base_matches, compile_base};
use stream_correlation::error::CorrelationError;


const LOGON_FAILED: &str = include_str!("../../../ecs-normalise/tests/snapshots/winsec_4625.json");


const LOGON_OK: &str = include_str!("../../../ecs-normalise/tests/snapshots/winsec_4624.json");


const FAILURE_SECONDS: [i64; 3] = [1, 2, 3];


fn rule(logsource: &str, detection: &str) -> String {
    format!("title: Security rule\nlogsource:\n{logsource}detection:\n  selection:\n{detection}  condition: selection\n")
}


fn security_rule(detection: &str) -> String {
    rule("  product: windows\n  service: security\n", detection)
}


fn matches(text: &str, event: &Value) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(base_matches(&compile_base(text, None, &mapping()?)?, event))
}


fn sigma_error(text: &str) -> Result<SigmaError, Box<dyn std::error::Error>> {
    match compile_base(text, None, &mapping()?) {
        Ok(_) => Err("the rule was accepted".into()),
        Err(CorrelationError::Sigma(error)) => Ok(error),
        Err(other) => Err(format!("not a Sigma error: {other}").into()),
    }
}


fn set(event: &mut Value, pointer: &str, value: Value) -> TestResult {
    *event.pointer_mut(pointer).ok_or("no such field in the event")? = value;
    Ok(())
}


fn failed_logon(second: i64, id: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut event: Value = serde_json::from_str(LOGON_FAILED)?;
    set(&mut event, "/@timestamp", json!(stamp(second)))?;
    set(
        &mut event,
        "/event",
        json!({"id": id, "code": "4625", "category": ["authentication"], "provider": "Microsoft-Windows-Security-Auditing"}),
    )?;
    Ok(event)
}


#[test]
fn a_4625_rule_matches_only_4625() -> TestResult {
    let failed: Value = serde_json::from_str(LOGON_FAILED)?;
    let succeeded: Value = serde_json::from_str(LOGON_OK)?;
    let text = security_rule("    EventID: 4625\n");
    assert!(matches(&text, &failed)?);
    assert!(!matches(&text, &succeeded)?);
    let filtered = security_rule("    EventID: 4625\n    TargetUserName|endswith: ob\n");
    assert!(matches(&filtered, &failed)?);
    Ok(())
}


#[test]
fn a_list_of_ids_is_an_or_and_text_ids_are_kept() -> TestResult {
    let failed: Value = serde_json::from_str(LOGON_FAILED)?;
    let succeeded: Value = serde_json::from_str(LOGON_OK)?;
    let list = security_rule("    EventID:\n      - 4624\n      - 4625\n");
    assert!(matches(&list, &failed)? && matches(&list, &succeeded)?);
    let prefix = security_rule("    EventID|startswith: '46'\n");
    assert!(matches(&prefix, &failed)? && matches(&prefix, &succeeded)?);
    let other = security_rule("    EventID|startswith: '47'\n");
    assert!(!matches(&other, &failed)?);
    Ok(())
}


#[test]
fn the_provider_and_the_os_are_required_and_the_category_is_not() -> TestResult {
    let text = security_rule("    EventID: 4625\n");
    let mut other_provider: Value = serde_json::from_str(LOGON_FAILED)?;
    set(&mut other_provider, "/event/provider", json!("Some-Other-Provider"))?;
    assert!(!matches(&text, &other_provider)?);
    let mut no_provider: Value = serde_json::from_str(LOGON_FAILED)?;
    set(&mut no_provider, "/event/provider", Value::Null)?;
    assert!(!matches(&text, &no_provider)?);
    let mut linux: Value = serde_json::from_str(LOGON_FAILED)?;
    set(&mut linux, "/host/os/type", json!("linux"))?;
    assert!(!matches(&text, &linux)?);
    let mut other_category: Value = serde_json::from_str(LOGON_FAILED)?;
    set(&mut other_category, "/event/category", json!(["process"]))?;
    assert!(matches(&text, &other_category)?);
    Ok(())
}


#[test]
fn refusals_follow_sigma_sql() -> TestResult {
    let both = rule("  category: process_creation\n  service: security\n", "    EventID: 4625\n");
    assert!(matches!(sigma_error(&both)?, SigmaError::Unsupported { .. }));
    let neither = rule("  product: windows\n", "    EventID: 4625\n");
    assert!(matches!(sigma_error(&neither)?, SigmaError::Unsupported { .. }));
    let unknown = rule("  product: windows\n  service: nothing\n", "    EventID: 4625\n");
    assert!(matches!(sigma_error(&unknown)?, SigmaError::Unsupported { .. }));
    let label = sigma_error(&security_rule("    LogonType: 3\n"))?;
    assert!(
        matches!(&label, SigmaError::UnmappedField { category, .. } if category == "security"),
        "{label}"
    );
    ["EventID: 4.5", "EventID: true", "EventID: null", "EventID: [4624, 4.5]"]
        .iter()
        .try_for_each(|detection| -> TestResult {
            let refused = sigma_error(&security_rule(&format!("    {detection}\n")))?;
            assert!(matches!(refused, SigmaError::BadValue { .. }), "{detection}: {refused}");
            Ok(())
        })
}


#[test]
fn the_stream_agrees_with_the_sql_compiler() -> TestResult {
    let failed: Value = serde_json::from_str(LOGON_FAILED)?;
    let succeeded: Value = serde_json::from_str(LOGON_OK)?;
    let parsed = parse_mapping(MAPPING)?;
    let cases = [
        ("    EventID: 4625\n", "`event.code` ilike '4625'", true, false),
        (
            "    EventID:\n      - 4624\n      - 4625\n",
            "`event.code` ilike '4624' OR `event.code` ilike '4625'",
            true,
            true,
        ),
        ("    EventID|startswith: '46'\n", "`event.code` ilike '46%'", true, true),
        ("    EventID: '4625'\n    SubjectUserName: bob\n", "`user.name` ilike 'bob'", true, false),
    ];
    cases.iter().try_for_each(|(detection, fragment, on_failed, on_ok)| -> TestResult {
        let text = security_rule(detection);
        let sql = compile_rule(&text, &parsed, &SqlOptions::default())?;
        assert!(sql.contains(fragment), "{sql}");
        assert!(sql.contains("`event.provider` = 'Microsoft-Windows-Security-Auditing'"), "{sql}");
        assert_eq!(matches(&text, &failed)?, *on_failed, "{detection}");
        assert_eq!(matches(&text, &succeeded)?, *on_ok, "{detection}");
        Ok(())
    })
}


const BASE_RULE: &str = "title: Failed logon
id: failed-logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
";


const BRUTE_FORCE: &str = "title: Brute force logon
id: logon-brute-force
correlation:
  type: event_count
  rules:
    - failed-logon
  group-by:
    - user.name
    - source.ip
  timespan: 5m
  condition:
    gte: 3
";


#[test]
fn brute_force_fires_at_its_threshold_for_one_user_and_source() -> TestResult {
    let bench = bench(&[BASE_RULE, BRUTE_FORCE])?;
    let succeeded: Value = serde_json::from_str(LOGON_OK)?;
    assert!(feed(&bench.engine, &succeeded).is_empty());
    let mut other_source = failed_logon(0, "other")?;
    set(&mut other_source, "/source/ip", json!("10.0.0.10"))?;
    assert!(feed(&bench.engine, &other_source).is_empty());
    let alerts: Vec<usize> = FAILURE_SECONDS
        .iter()
        .map(|second| failed_logon(*second, &format!("f{second}")).map(|event| feed(&bench.engine, &event).len()))
        .collect::<Result<_, _>>()?;
    assert_eq!(alerts, vec![0, 0, 1]);
    Ok(())
}
