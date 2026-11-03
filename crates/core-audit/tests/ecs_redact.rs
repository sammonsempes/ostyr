#[path = "support/failing_reader.rs"]
mod failing_reader;
#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/log_builder.rs"]
mod log_builder;
#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::ecs::{category, ecs_outcome, export, to_ecs};
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::Outcome;
use core_audit::redact::{is_sensitive, redact_parameters, redact_url_password, REDACTED};
use failing_reader::flaky_reader;
use failing_writer::FailingWriter;
use log_builder::build_log;
use sample::entry;
use serde_json::Value;
use std::io::BufReader;
use types::TestResult;


const RECORD_COUNT: usize = 3;


const HASH_LENGTH: usize = 64;


const REMOVED_LINE: usize = 2;


fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}


#[test]
fn export_writes_one_ecs_event_per_record() -> TestResult {
    let (lines, _) = build_log(RECORD_COUNT)?;
    let mut out = Vec::new();
    let count = export(lines.concat().as_bytes(), &mut out, None)?;
    assert_eq!(count, RECORD_COUNT);
    let events: Vec<Value> = String::from_utf8(out)?.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
    let first = events.first().ok_or("no event")?;
    assert_eq!(at(first, "/@timestamp"), "2023-11-14T22:13:20Z");
    assert_eq!(at(first, "/event/category/0"), "configuration");
    assert_eq!(at(first, "/event/action"), "config.update");
    assert_eq!(at(first, "/event/outcome"), "success");
    assert_eq!(at(first, "/event/id").as_str().map(str::len), Some(HASH_LENGTH));
    assert_eq!(at(first, "/trace/id"), "request-0");
    assert_eq!(at(first, "/event/reason"), "ticket 42");
    assert_eq!(at(first, "/user/id"), "user-0");
    assert_eq!(at(first, "/service/name"), "iam");
    assert_eq!(at(first, "/organization/id"), "tenant-a");
    assert_eq!(at(first, "/ostyr/actor_kind"), "user");
    assert_eq!(at(first, "/ecs/version"), "8.11");
    Ok(())
}


#[test]
fn empty_log_exports_nothing() -> TestResult {
    let mut out = Vec::new();
    assert_eq!(export(&b""[..], &mut out, None)?, 0);
    assert!(out.is_empty());
    Ok(())
}


#[test]
fn iam_actions_and_denied_outcomes_are_mapped() -> TestResult {
    assert_eq!(category("iam.role.grant"), "iam");
    assert_eq!(category("auth.login"), "iam");
    assert_eq!(category("config.update"), "configuration");
    assert_eq!(ecs_outcome(Outcome::Denied), "failure");
    assert_eq!(ecs_outcome(Outcome::Failure), "failure");
    assert_eq!(ecs_outcome(Outcome::Success), "success");
    let log = genesis_log(Vec::new());
    let mut denied = entry(0)?;
    denied.action = "auth.login".to_owned();
    denied.outcome = Outcome::Denied;
    denied.justification = None;
    let event = to_ecs(&append(&log, denied)?);
    assert_eq!(at(&event, "/event/category/0"), "iam");
    assert_eq!(at(&event, "/event/outcome"), "failure");
    assert_eq!(at(&event, "/ostyr/outcome"), "denied");
    assert_eq!(at(&event, "/event/reason"), Value::Null);
    Ok(())
}


#[test]
fn export_refuses_a_broken_chain() -> TestResult {
    let (mut lines, _) = build_log(RECORD_COUNT)?;
    lines.remove(1);
    let mut out = Vec::new();
    assert!(matches!(
        export(lines.concat().as_bytes(), &mut out, None),
        Err(AuditError::Broken { line: REMOVED_LINE, .. })
    ));
    assert!(out.is_empty());
    Ok(())
}


#[test]
fn export_reports_read_and_write_failures() -> TestResult {
    let (lines, _) = build_log(1)?;
    let mut sink = FailingWriter {
        fail_write: true,
        fail_flush: false,
    };
    assert!(matches!(export(lines.concat().as_bytes(), &mut sink, None), Err(AuditError::Io(_))));
    assert!(matches!(
        export(BufReader::new(flaky_reader(Vec::new(), true)), &mut Vec::new(), None),
        Err(AuditError::Io(_))
    ));
    Ok(())
}


#[test]
fn sensitive_keys_and_values_are_redacted() {
    let parameters = [
        ("Password".to_owned(), "hunter2".to_owned()),
        ("api_token".to_owned(), "abc".to_owned()),
        ("SSH_KEY".to_owned(), "k".to_owned()),
        ("note".to_owned(), "Bearer abc.def".to_owned()),
        ("cert".to_owned(), "-----BEGIN PRIVATE KEY-----".to_owned()),
        ("header".to_owned(), "Basic dXNlcjpwYXNz".to_owned()),
        ("name".to_owned(), "visible".to_owned()),
    ]
    .into();
    let redacted = redact_parameters(&parameters);
    assert_eq!(redacted.get("Password").map(String::as_str), Some(REDACTED));
    assert_eq!(redacted.get("api_token").map(String::as_str), Some(REDACTED));
    assert_eq!(redacted.get("SSH_KEY").map(String::as_str), Some(REDACTED));
    assert_eq!(redacted.get("note").map(String::as_str), Some(REDACTED));
    assert_eq!(redacted.get("cert").map(String::as_str), Some(REDACTED));
    assert_eq!(redacted.get("header").map(String::as_str), Some(REDACTED));
    assert_eq!(redacted.get("name").map(String::as_str), Some("visible"));
    assert!(!is_sensitive("name", "visible"));
}


#[test]
fn appended_records_never_contain_secrets() -> TestResult {
    let log = genesis_log(Vec::new());
    let mut secret = entry(0)?;
    secret.parameters = [
        ("password".to_owned(), "hunter2".to_owned()),
        ("note".to_owned(), "Bearer topsecret".to_owned()),
    ]
    .into();
    let record = append(&log, secret)?;
    let state = log.state.into_inner()?;
    let text = String::from_utf8(state.writer)?;
    assert!(!text.contains("hunter2"));
    assert!(!text.contains("topsecret"));
    assert_eq!(record.parameters.get("password").map(String::as_str), Some(REDACTED));
    Ok(())
}


#[test]
fn export_checks_the_anchored_head() -> TestResult {
    let (lines, head) = build_log(RECORD_COUNT)?;
    let text = lines.concat();
    assert_eq!(export(text.as_bytes(), &mut Vec::new(), Some(&head))?, RECORD_COUNT);
    let mut out = Vec::new();
    assert!(matches!(
        export(text.as_bytes(), &mut out, Some("abc")),
        Err(AuditError::HeadMismatch { .. })
    ));
    assert!(out.is_empty());
    Ok(())
}


#[test]
fn credentials_are_redacted_whatever_their_case_or_shape() -> TestResult {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln-_x";
    let parameters = [
        ("a".to_owned(), "bearer abc".to_owned()),
        ("b".to_owned(), "BASIC dXNlcg==".to_owned()),
        ("c".to_owned(), "-----begin private key-----".to_owned()),
        ("pwd".to_owned(), "x".to_owned()),
        ("auth".to_owned(), "x".to_owned()),
        ("Authorization".to_owned(), "x".to_owned()),
        ("Cookie".to_owned(), "x".to_owned()),
        ("d".to_owned(), jwt.to_owned()),
        ("e".to_owned(), "eyJabc.def".to_owned()),
        ("f".to_owned(), "eyJabc..ghi".to_owned()),
        ("g".to_owned(), "eyJa.b.c.d".to_owned()),
        ("h".to_owned(), "eyJa.b!.c".to_owned()),
        ("url".to_owned(), "postgres://admin:s3cret@db.local:5432/app?x=1".to_owned()),
        ("plain".to_owned(), "https://example.org/path@x:y".to_owned()),
        ("nopass".to_owned(), "ssh://git@host/repo".to_owned()),
        ("bare".to_owned(), "https://host".to_owned()),
    ]
    .into();
    let redacted = redact_parameters(&parameters);
    let value = |key: &str| redacted.get(key).map(String::as_str);
    ["a", "b", "c", "pwd", "auth", "Authorization", "Cookie", "d"]
        .iter()
        .for_each(|key| assert_eq!(value(key), Some(REDACTED), "{key}"));
    assert_eq!(value("e"), Some("eyJabc.def"));
    assert_eq!(value("f"), Some("eyJabc..ghi"));
    assert_eq!(value("g"), Some("eyJa.b.c.d"));
    assert_eq!(value("h"), Some("eyJa.b!.c"));
    assert_eq!(value("url"), Some("postgres://admin:[REDACTED]@db.local:5432/app?x=1"));
    assert_eq!(value("plain"), Some("https://example.org/path@x:y"));
    assert_eq!(value("nopass"), Some("ssh://git@host/repo"));
    assert_eq!(value("bare"), Some("https://host"));
    assert_eq!(redact_url_password("no url"), "no url");
    Ok(())
}
