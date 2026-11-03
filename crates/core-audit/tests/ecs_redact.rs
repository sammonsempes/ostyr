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
use core_audit::verify::{same_as_first_pass, VerifyReport};
use core_redact::value::REDACTED;
use failing_reader::flaky_reader;
use failing_writer::FailingWriter;
use log_builder::build_log;
use sample::entry;
use serde_json::Value;
use std::cell::Cell;
use std::io::{self, BufReader, Cursor};
use types::TestResult;


const RECORD_COUNT: usize = 3;


const HASH_LENGTH: usize = 64;


const REMOVED_LINE: usize = 2;


fn replay(data: Vec<u8>) -> impl FnMut() -> io::Result<Cursor<Vec<u8>>> {
    move || Ok(Cursor::new(data.clone()))
}


fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}


#[test]
fn export_writes_one_ecs_event_per_record() -> TestResult {
    let (lines, _) = build_log(RECORD_COUNT)?;
    let mut out = Vec::new();
    let count = export(replay(lines.concat().into_bytes()), &mut out, None)?;
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
    assert_eq!(export(replay(Vec::new()), &mut out, None)?, 0);
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
        export(replay(lines.concat().into_bytes()), &mut out, None),
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
    assert!(matches!(
        export(replay(lines.concat().into_bytes()), &mut sink, None),
        Err(AuditError::Io(_))
    ));
    assert!(matches!(
        export(|| Ok(BufReader::new(flaky_reader(Vec::new(), true))), &mut Vec::new(), None),
        Err(AuditError::Io(_))
    ));
    Ok(())
}


#[test]
fn export_reports_failures_of_the_second_pass() -> TestResult {
    let (lines, _) = build_log(RECORD_COUNT)?;
    let data = lines.concat().into_bytes();
    let corrupt = vec![b'x'; data.len()];
    let mut out = Vec::new();
    let calls = Cell::new(0);
    let reopen_fails = || {
        calls.set(calls.get() + 1);
        if calls.get() == 1 {
            Ok(Cursor::new(data.clone()))
        } else {
            Err(io::Error::other("injected reopen failure"))
        }
    };
    assert!(matches!(export(reopen_fails, &mut out, None), Err(AuditError::Io(_))));
    calls.set(0);
    let read_fails = || {
        calls.set(calls.get() + 1);
        Ok(BufReader::new(flaky_reader(data.clone(), calls.get() > 1)))
    };
    assert!(matches!(export(read_fails, &mut out, None), Err(AuditError::Io(_))));
    calls.set(0);
    let changed = || {
        calls.set(calls.get() + 1);
        Ok(Cursor::new(if calls.get() > 1 { corrupt.clone() } else { data.clone() }))
    };
    assert!(matches!(export(changed, &mut out, None), Err(AuditError::Broken { line: 1, .. })));
    Ok(())
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
    assert_eq!(export(replay(text.clone().into_bytes()), &mut Vec::new(), Some(&head))?, RECORD_COUNT);
    let mut out = Vec::new();
    assert!(matches!(
        export(replay(text.clone().into_bytes()), &mut out, Some("abc")),
        Err(AuditError::HeadMismatch { .. })
    ));
    assert!(out.is_empty());
    Ok(())
}


const OTHER_CHAIN_OFFSET: usize = 10;


fn swapped_chain() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let log = genesis_log(Vec::new());
    (0..RECORD_COUNT).try_for_each(|index| {
        entry(index + OTHER_CHAIN_OFFSET)
            .map_err(|error| error.to_string())
            .and_then(|new| append(&log, new).map(|_| ()).map_err(|error| error.to_string()))
    })?;
    Ok(vec![String::from_utf8(log.state.into_inner()?.writer)?])
}


#[test]
fn export_refuses_an_input_that_changes_between_the_passes() -> TestResult {
    let (lines, _) = build_log(RECORD_COUNT)?;
    let (longer, _) = build_log(RECORD_COUNT + 1)?;
    let first = lines.concat().into_bytes();
    let shorter = lines.iter().take(RECORD_COUNT - 1).cloned().collect::<String>().into_bytes();
    let second_pass_inputs = [shorter, longer.concat().into_bytes(), swapped_chain()?.concat().into_bytes()];
    second_pass_inputs.iter().try_for_each(|second| -> TestResult {
        let calls = Cell::new(0);
        let changing = || {
            calls.set(calls.get() + 1);
            Ok(Cursor::new(if calls.get() > 1 { second.clone() } else { first.clone() }))
        };
        assert!(matches!(export(changing, &mut Vec::new(), None), Err(AuditError::HeadMismatch { .. })));
        Ok(())
    })
}


#[test]
fn a_changed_head_or_count_is_refused() {
    let report = VerifyReport {
        records: RECORD_COUNT,
        head: "abc".to_owned(),
    };
    assert!(same_as_first_pass(&report, "abc".to_owned(), RECORD_COUNT).is_ok());
    assert!(same_as_first_pass(&report, "abc".to_owned(), RECORD_COUNT + 1).is_err());
    assert!(same_as_first_pass(&report, "abd".to_owned(), RECORD_COUNT).is_err());
}
