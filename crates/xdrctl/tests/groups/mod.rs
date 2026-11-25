use super::{
    alerts_stub, store_alerts_session, FAILURE, STATUS_ERROR, STATUS_FORBIDDEN, STATUS_OK, STATUS_TOO_MANY, STATUS_UNAUTHORIZED, SUCCESS,
    USAGE_FAILURE,
};
use crate::support::{invoke, offline_args, TestResult};
use serde_json::{json, Value};
use std::cell::RefCell;
use tempfile::tempdir;


const STATUS_UNAVAILABLE: u16 = 503;


const COUNT: u64 = 5;


const DUPLICATES: u64 = 4;


const READ: u64 = 7;


const THREE_LINES: usize = 3;


const HUGE_HOST: usize = 65_536;


const SHOWN_LIMIT: usize = 1_000;


fn static_text(value: &Value) -> &'static str {
    Box::leak(value.to_string().into_boxed_str())
}


fn group(host: Option<&str>, user: Option<&str>, omitted: bool) -> Value {
    json!({
        "rule_id": "r1", "host_name": host, "user_name": user, "representative": "a1", "alert_ids": ["a1"], "omitted": omitted,
        "alert_count": COUNT, "duplicates": DUPLICATES, "first_time": "2026-01-01T00:00:00Z", "last_time": "2026-01-02T00:00:00Z",
        "max_severity": "high", "cut_at_older": omitted
    })
}


fn reply(complete: bool, oldest: Option<&str>, groups: Vec<Value>) -> &'static str {
    static_text(&json!({ "groups": groups, "complete": complete, "alerts_read": READ, "oldest_read": oldest, "future_field": 1 }))
}


#[test]
fn two_groups_and_the_footer() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body = reply(
        true,
        Some("2025-12-31T00:00:00Z"),
        vec![group(Some("web01"), None, false), group(None, Some("alice"), true)],
    );
    let outcome = invoke(&offline_args(dir.path(), &["alerts", "groups"]), "", &alerts_stub(&seen, STATUS_OK, body))?;
    assert_eq!(outcome.code, SUCCESS);
    let lines: Vec<&str> = outcome.out.lines().collect();
    assert_eq!(
        lines,
        vec![
            "r1\tweb01\t-\t5\t4\thigh\t2026-01-01T00:00:00Z\t2026-01-02T00:00:00Z\tomitted no\tcut_at_older no",
            "r1\t-\talice\t5\t4\thigh\t2026-01-01T00:00:00Z\t2026-01-02T00:00:00Z\tomitted yes\tcut_at_older yes",
            "alerts read 7, complete yes, oldest 2025-12-31T00:00:00Z",
        ]
    );
    assert_eq!(seen.borrow().as_slice(), ["https://example.test/alert-groups Some(\"tok\")"]);
    Ok(())
}


#[test]
fn incomplete_puts_the_notice_first() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body = reply(false, None, vec![group(Some("h"), None, false)]);
    let outcome = invoke(&offline_args(dir.path(), &["alerts", "groups"]), "", &alerts_stub(&seen, STATUS_OK, body))?;
    let lines: Vec<&str> = outcome.out.lines().collect();
    assert!(lines.first().is_some_and(|line| line.starts_with("INCOMPLETE:")));
    assert_eq!(lines.last(), Some(&"alerts read 7, complete no, oldest none"));
    assert_eq!(lines.len(), THREE_LINES);
    Ok(())
}


#[test]
fn hostile_values_print_escaped_and_bounded() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let hostile = "\u{1b}[2J\r\u{202e}";
    let huge = format!("{hostile}{}", "x".repeat(HUGE_HOST));
    let body = reply(true, Some(hostile), vec![group(Some(&huge), Some(hostile), false)]);
    let text = invoke(&offline_args(dir.path(), &["alerts", "groups"]), "", &alerts_stub(&seen, STATUS_OK, body))?;
    assert!(!text.out.contains(['\u{1b}', '\r', '\u{202e}']));
    assert!(text.out.contains("\\u{1b}[2J\\u{d}\\u{202e}"));
    assert!(text.out.contains("...[cut]"));
    assert!(text.out.len() < SHOWN_LIMIT);
    let rule = reply(
        true,
        None,
        vec![json!({"rule_id": hostile, "host_name": null, "user_name": null, "representative": "a",
        "alert_ids": [], "omitted": false, "alert_count": 1, "duplicates": 0, "first_time": hostile, "last_time": hostile,
        "max_severity": hostile, "cut_at_older": false})],
    );
    let other = invoke(&offline_args(dir.path(), &["alerts", "groups"]), "", &alerts_stub(&seen, STATUS_OK, rule))?;
    assert!(!other.out.contains(['\u{1b}', '\r', '\u{202e}']));
    let json = invoke(
        &offline_args(dir.path(), &["--output", "json", "alerts", "groups"]),
        "",
        &alerts_stub(&seen, STATUS_OK, body),
    )?;
    assert!(!json.out.contains(['\u{1b}', '\u{202e}']));
    Ok(())
}


#[test]
fn json_equals_the_reply() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body = reply(false, Some("t"), vec![group(Some("h"), Some("u"), false)]);
    let outcome = invoke(
        &offline_args(dir.path(), &["--output", "json", "alerts", "groups"]),
        "",
        &alerts_stub(&seen, STATUS_OK, body),
    )?;
    assert_eq!(serde_json::from_str::<Value>(&outcome.out)?, serde_json::from_str::<Value>(body)?);
    Ok(())
}


#[test]
fn extra_argument_is_a_usage_error() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let outcome = invoke(
        &offline_args(dir.path(), &["alerts", "groups", "extra"]),
        "",
        &alerts_stub(&seen, STATUS_OK, "{}"),
    )?;
    assert_eq!(outcome.code, USAGE_FAILURE);
    assert!(seen.borrow().is_empty());
    Ok(())
}


#[test]
fn statuses_map_to_fixed_messages() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body = "{\"error\":{\"code\":\"c\",\"message\":\"MARKER\"}}";
    for (status, expected) in [
        (STATUS_UNAUTHORIZED, "not valid"),
        (STATUS_FORBIDDEN, "permission denied"),
        (STATUS_TOO_MANY, "too many"),
        (STATUS_UNAVAILABLE, "alert groups unavailable, retry later"),
    ] {
        let outcome = invoke(&offline_args(dir.path(), &["alerts", "groups"]), "", &alerts_stub(&seen, status, body))?;
        assert_eq!(outcome.code, FAILURE);
        assert!(outcome.err.contains(expected));
        assert!(!outcome.err.contains("MARKER"));
    }
    let other = invoke(
        &offline_args(dir.path(), &["alerts", "groups"]),
        "",
        &alerts_stub(&seen, STATUS_ERROR, body),
    )?;
    assert!(other.err.contains("500"));
    Ok(())
}


#[test]
fn a_reply_missing_complete_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body = "{\"groups\":[],\"alerts_read\":0,\"oldest_read\":null}";
    let outcome = invoke(&offline_args(dir.path(), &["alerts", "groups"]), "", &alerts_stub(&seen, STATUS_OK, body))?;
    assert_eq!(outcome.code, FAILURE);
    assert!(outcome.err.contains("unexpected reply"));
    assert!(outcome.out.is_empty());
    Ok(())
}
