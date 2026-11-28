#![cfg(unix)]

#[path = "retro/types.rs"]
mod types;


use alerts::store::INVISIBLE_CHARACTERS;
use detection::error::RetroError;
use detection::retro::{
    absorb, body_failure, check_refusal, entity_of, event_of, fetch_with, hash_expression, hash_part, id_allowed, read_changed, read_ids, refusal,
    retro_identity, retro_projection, retro_run, retro_statement, run_retro, send_request, validate_retro, window_epochs, EventRow, HashKind,
    RetroIds, RetroOutcome, RetroQuery, RetroReply, RetroRequest, RetroSettings, HASH_COLUMNS, MAX_RETRO_BYTES, MAX_RETRO_DAYS, MAX_RETRO_ROWS,
    MAX_ROW_BYTES,
};
use sha2::{Digest, Sha256};
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::pins;
use siem_schema::schema::default_columns;
use sigma_sql::mapping::{parse_mapping, FieldMapping};
use std::cell::RefCell;
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::macros::datetime;
use time::OffsetDateTime;
use tokio::net::TcpSocket;
use types::{Run, Scripted, TestResult};
use ureq::http::StatusCode;


const MAPPING: &str = include_str!("../../sigma-sql/mappings/ecs.yaml");


const RULE: &str = include_str!("../../sigma-sql/tests/rules/winsec_4625.yml");


const START: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


const END: OffsetDateTime = datetime!(2026-11-06 00:00:00 UTC);


const START_EPOCH: &str = "1793664000";


const END_EPOCH: &str = "1793923200";


const PASSWORD: &str = "RETROPW-77c1";


const TIMEOUT_MS: u64 = 60_000;


const ROWS: usize = 3;


const CHECK_ROWS: u64 = 64;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const OVER_BYTES: usize = 67_200_000;


const HTTP_OK: u16 = 200;


const EXEC_SECONDS: u32 = 30;


const READ_ROWS: u64 = 1_000_000;


const IDS_READ: usize = 2;


const REFUSED: usize = 2;


const WIDE_CAP: usize = 8;


const NONE_SENT: usize = 0;


const BYTE_ZERO: u8 = 0;


const SECRET_MODE: u32 = 0o600;


const SERVER_ERROR: u16 = 500;


const PROFILE_CODE: u32 = 164;


const TIMEOUT_CODE: u32 = 159;


const TOO_SLOW_CODE: u32 = 160;


const ROWS_CODE: u32 = 158;


const RESULT_ROWS_CODE: u32 = 396;


const OTHER_CODE: u32 = 60;


const OVER_USER_BYTES: usize = 129;


const OVER_TIMEOUT_MS: u64 = 300_001;


const OVER_EXEC_SECONDS: u32 = 301;


const OVER_ROWS_TO_READ: u64 = 10_000_000_001;


const START_SECONDS: u32 = 1_793_664_000;


const END_SECONDS: u32 = 1_793_923_200;


const BEFORE_EPOCH: OffsetDateTime = datetime!(1969-12-31 00:00:00 UTC);


const FAR_FUTURE: OffsetDateTime = datetime!(2200-01-01 00:00:00 UTC);


const OVER_CHECK_BYTES: usize = 5000;


const BAD_UTF8: [u8; 2] = [0xff, 0xfe];


const HASH_WIDTH: usize = 64;


const SECOND_ROW: usize = 2;


const THIRD_ROW: usize = 3;


const FOURTH_ROW: usize = 4;


const BAD_FLAG: u8 = 2;


const BASE_MS: i64 = 1_793_664_000_000;


const ENTITY_LIMIT: usize = 256;


const ID_KEEP: usize = 64;


const MEGABYTE: usize = 1_048_576;


const KNOWN_MS: i64 = 1_793_664_000_123;


const ID_CUT: usize = 63;


const KNOWN_HASH: &str = "74fa251e3d1796528576b6dc40c9ab9dd1b9269bb8a5c2b4d7c1c36e2c0b717b";


fn settings() -> RetroSettings {
    RetroSettings {
        url: "http://127.0.0.1:1".to_owned(),
        user: "retro_reader".to_owned(),
        password_file: "unused".into(),
        ca_file: None,
        database: "ostyr".to_owned(),
        timeout_ms: TIMEOUT_MS,
        max_rows: ROWS,
        max_execution_seconds: EXEC_SECONDS,
        max_rows_to_read: READ_ROWS,
    }
}


fn mapping() -> Result<FieldMapping, Box<dyn Error>> {
    Ok(parse_mapping(MAPPING)?)
}


fn query() -> RetroQuery {
    RetroQuery {
        rule_text: RULE.to_owned(),
        tenant: "tenant-a".to_owned(),
        start: START,
        end: END,
    }
}


fn clean_reply() -> String {
    let names: Vec<&str> = pins(&[], CHECK_ROWS)
        .iter()
        .map(|(name, _)| *name)
        .chain([
            "max_execution_time",
            "max_rows_to_read",
            "readonly",
            "http_write_exception_in_output_format",
            "database",
        ])
        .collect();
    format!("{}\n", names.join("\n"))
}


fn reply(status: u16, code: Option<u32>, body: Vec<u8>) -> Result<RetroReply, InsertClass> {
    Ok(RetroReply {
        status: StatusCode::from_u16(status).map_err(|_| InsertClass::Rejected)?,
        code,
        body: Box::new(Cursor::new(body)),
    })
}


fn ok_text(text: &str) -> Result<RetroReply, InsertClass> {
    reply(HTTP_OK, None, text.as_bytes().to_vec())
}


fn hash_of(index: usize) -> String {
    format!("{index:0HASH_WIDTH$x}")
}


fn row_value(index: usize, id: &str, valid: u8, host: &str, user: &str) -> serde_json::Value {
    serde_json::json!({
        "ret_ms": (BASE_MS + index as i64).to_string(),
        "ret_hash": hash_of(index),
        "ret_id": id,
        "ret_id_chars": id.chars().count(),
        "ret_id_valid": valid,
        "ret_host": host,
        "ret_host_chars": host.chars().count(),
        "ret_user": user,
        "ret_user_chars": user.chars().count(),
    })
}


fn row_json(index: usize, id: &str, valid: u8, host: &str, user: &str) -> String {
    row_value(index, id, valid, host, user).to_string()
}


fn id_lines(ids: &[&str]) -> String {
    ids.iter()
        .enumerate()
        .map(|(index, id)| format!("{}\n", row_json(index + 1, id, 1, "host-1", "user-1")))
        .collect()
}


fn identities(found: &RetroIds) -> Vec<String> {
    found.events.iter().map(|event| event.identity.clone()).collect()
}


fn identity(index: usize, id: &str) -> String {
    format!("{id}:{}", hash_of(index))
}


fn into_complete(outcome: RetroOutcome) -> Result<RetroIds, Box<dyn Error>> {
    match outcome {
        RetroOutcome::Complete(found) => Ok(found),
        RetroOutcome::RowCap { .. } => Err("row cap".into()),
    }
}


fn complete(body: String) -> Result<RetroIds, Box<dyn Error>> {
    into_complete(read_ids(with_body(Box::new(Cursor::new(body.into_bytes()))), WIDE_CAP)?)
}


fn run_script(script: Vec<Result<RetroReply, InsertClass>>, settings: &RetroSettings, query: &RetroQuery) -> Result<Run, Box<dyn Error>> {
    let queue: RefCell<Scripted> = RefCell::new(script.into());
    let seen: RefCell<Vec<RetroRequest>> = RefCell::new(Vec::new());
    let outcome = retro_run(settings, &mapping()?, query, &|| Duration::ZERO, &|request| {
        seen.borrow_mut().push(request.clone());
        queue.borrow_mut().pop_front().unwrap_or(Err(InsertClass::Unavailable))
    });
    Ok((outcome, seen.into_inner()))
}


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::ConnectionReset, "secret transport text"))
    }
}


struct TimingOut;


impl Read for TimingOut {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::TimedOut, "secret"))
    }
}


fn with_body(body: Box<dyn Read>) -> RetroReply {
    RetroReply {
        status: StatusCode::OK,
        code: None,
        body,
    }
}


#[test]
fn a_run_checks_the_profile_then_reads_the_ids_in_order() -> TestResult {
    let (outcome, seen) = run_script(vec![ok_text(&clean_reply()), ok_text(&id_lines(&["e1", "e2"]))], &settings(), &query())?;
    let found = into_complete(outcome?)?;
    assert_eq!(identities(&found), vec![identity(1, "e1"), identity(SECOND_ROW, "e2")]);
    assert_eq!((found.refused, found.rows), (0, IDS_READ));
    let first = found.events.first().ok_or("no event")?;
    assert_eq!((first.event_ms, first.event_time.as_str()), (BASE_MS + 1, "2026-11-03T00:00:00.001Z"));
    assert_eq!(seen.len(), IDS_READ);
    let check = seen.first().ok_or("no check")?;
    assert!(check.statement.contains("FROM `system`.`settings` WHERE `changed` SETTINGS "));
    let read = seen.get(1).ok_or("no read")?;
    assert!(read
        .statement
        .starts_with("SELECT toString(toUnixTimestamp64Milli(`@timestamp`)) AS `ret_ms`, lower(hex(SHA256(concat("));
    assert!(read
        .statement
        .contains(" AS `ret_hash`, if(isValidUTF8(`event.id`), leftUTF8(`event.id`, 64), '') AS `ret_id`, "));
    assert!(read
        .statement
        .contains("lengthUTF8(`event.id`) AS `ret_id_chars`, isValidUTF8(`event.id`) AS `ret_id_valid`, "));
    assert!(read
        .statement
        .contains("leftUTF8(`host.name`, 257), '') AS `ret_host`, lengthUTF8(`host.name`) AS `ret_host_chars`, "));
    assert!(read
        .statement
        .contains("leftUTF8(`user.name`, 257), '') AS `ret_user`, lengthUTF8(`user.name`) AS `ret_user_chars` FROM `events` WHERE "));
    assert!(read
        .statement
        .contains("`tenant` = {tenant:String} AND `@timestamp` >= toDateTime({start:UInt32}, 'UTC')"));
    assert!(read
        .statement
        .contains("ORDER BY `@timestamp`, `ret_hash` LIMIT {limit:UInt64} SETTINGS max_execution_time = 30, max_rows_to_read = 1000000, "));
    assert!(read.statement.contains("max_result_rows = 4"));
    assert!(read.statement.ends_with("FORMAT JSONEachRow"));
    assert!(read.settings.contains(&("database", "ostyr".to_owned())));
    assert!(read.settings.contains(&("readonly", "2".to_owned())));
    assert_eq!(
        read.params,
        vec![
            ("tenant", "tenant-a".to_owned()),
            ("start", START_EPOCH.to_owned()),
            ("end", END_EPOCH.to_owned()),
            ("limit", "4".to_owned())
        ]
    );
    Ok(())
}


#[test]
fn more_rows_than_the_cap_is_a_named_row_cap_never_a_silent_cut() -> TestResult {
    let (result, _) = run_script(
        vec![ok_text(&clean_reply()), ok_text(&id_lines(&["e1", "e2", "e3", "e4"]))],
        &settings(),
        &query(),
    )?;
    let outcome = result?;
    assert!(
        matches!(&outcome, RetroOutcome::RowCap { found, cap } if *cap == ROWS && identities(found) == [identity(1, "e1"), identity(SECOND_ROW, "e2"), identity(THIRD_ROW, "e3")] && found.rows == ROWS + 1)
    );
    Ok(())
}


#[test]
fn exactly_the_cap_is_complete() -> TestResult {
    let (outcome, _) = run_script(
        vec![ok_text(&clean_reply()), ok_text(&id_lines(&["e1", "e2", "e3"]))],
        &settings(),
        &query(),
    )?;
    assert!(matches!(outcome?, RetroOutcome::Complete(found) if found.events.len() == ROWS));
    Ok(())
}


#[test]
fn a_server_that_sends_past_the_cap_plus_one_is_refused() -> TestResult {
    let (outcome, _) = run_script(
        vec![ok_text(&clean_reply()), ok_text(&id_lines(&["e1", "e2", "e3", "e4", "e5"]))],
        &settings(),
        &query(),
    )?;
    assert!(matches!(outcome, Err(RetroError::TooManyRows(ROWS))));
    Ok(())
}


#[test]
fn a_changed_setting_outside_the_pins_is_refused_before_the_read() -> TestResult {
    let dirty = format!("{}skip_unavailable_shards\n", clean_reply());
    let (outcome, seen) = run_script(vec![ok_text(&dirty), ok_text(&id_lines(&["e1"]))], &settings(), &query())?;
    assert!(matches!(outcome, Err(RetroError::ReaderProfileChanged(1))));
    assert_eq!(seen.len(), 1);
    Ok(())
}


#[test]
fn an_empty_settings_reply_is_refused_not_read_as_clean() -> TestResult {
    let (outcome, seen) = run_script(vec![ok_text(""), ok_text(&id_lines(&["e1"]))], &settings(), &query())?;
    assert!(matches!(outcome, Err(RetroError::ReaderProfileChanged(found)) if found > 0));
    assert_eq!(seen.len(), 1);
    Ok(())
}


#[test]
fn a_profile_refusal_of_the_check_is_reader_profile_changed() -> TestResult {
    let (outcome, _) = run_script(vec![reply(SERVER_ERROR, Some(PROFILE_CODE), Vec::new())], &settings(), &query())?;
    assert!(matches!(outcome, Err(RetroError::ReaderProfileChanged(1))));
    let (other, _) = run_script(vec![reply(SERVER_ERROR, Some(TIMEOUT_CODE), Vec::new())], &settings(), &query())?;
    assert!(matches!(other, Err(RetroError::Timeout)));
    Ok(())
}


#[test]
fn the_exception_code_picks_the_error_of_the_read() -> TestResult {
    let read = |code: u32| {
        run_script(
            vec![ok_text(&clean_reply()), reply(SERVER_ERROR, Some(code), b"Code: secret".to_vec())],
            &settings(),
            &query(),
        )
    };
    assert!(matches!(read(TIMEOUT_CODE)?.0, Err(RetroError::Timeout)));
    assert!(matches!(read(TOO_SLOW_CODE)?.0, Err(RetroError::Timeout)));
    assert!(matches!(read(ROWS_CODE)?.0, Err(RetroError::ReadLimit)));
    assert!(matches!(read(RESULT_ROWS_CODE)?.0, Err(RetroError::ReadLimit)));
    assert!(matches!(read(OTHER_CODE)?.0, Err(RetroError::Refused(_))));
    assert!(refusal(StatusCode::OK, None).is_none());
    assert!(check_refusal(StatusCode::OK, None).is_none());
    Ok(())
}


#[test]
fn a_transport_failure_is_a_fixed_class() -> TestResult {
    let (outcome, _) = run_script(vec![Err(InsertClass::Timeout)], &settings(), &query())?;
    assert!(matches!(outcome, Err(RetroError::Refused(InsertClass::Timeout))));
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let sent = RefCell::new(NONE_SENT);
    let outcome = fetch_with(
        &|_| {
            *sent.borrow_mut() += 1;
            ok_text("")
        },
        &settings(),
        &|| Duration::from_millis(TIMEOUT_MS),
        "SELECT 1",
        Vec::new(),
        refusal,
    );
    assert!(matches!(outcome, Err(RetroError::Timeout)));
    assert_eq!(*sent.borrow(), 0);
    Ok(())
}


#[test]
fn settings_are_checked_before_any_request() -> TestResult {
    let check = |changed: RetroSettings| -> Result<Option<String>, Box<dyn Error>> {
        let (outcome, seen) = run_script(vec![ok_text(&clean_reply())], &changed, &query())?;
        assert!(seen.is_empty());
        Ok(outcome.err().map(|error| error.to_string()))
    };
    let base = settings();
    assert!(check(RetroSettings {
        url: "ftp://x".to_owned(),
        ..base.clone()
    })?
    .is_some_and(|text| text.contains("url")));
    for (name, bad) in [
        (
            "user",
            RetroSettings {
                user: String::new(),
                ..base.clone()
            },
        ),
        (
            "user",
            RetroSettings {
                user: "a b".to_owned(),
                ..base.clone()
            },
        ),
        (
            "user",
            RetroSettings {
                user: "u".repeat(OVER_USER_BYTES),
                ..base.clone()
            },
        ),
        (
            "database",
            RetroSettings {
                database: "1x".to_owned(),
                ..base.clone()
            },
        ),
        (
            "timeout_ms",
            RetroSettings {
                timeout_ms: 0,
                ..base.clone()
            },
        ),
        (
            "timeout_ms",
            RetroSettings {
                timeout_ms: OVER_TIMEOUT_MS,
                ..base.clone()
            },
        ),
        ("max_rows", RetroSettings { max_rows: 0, ..base.clone() }),
        (
            "max_rows",
            RetroSettings {
                max_rows: MAX_RETRO_ROWS + 1,
                ..base.clone()
            },
        ),
        (
            "max_execution_seconds",
            RetroSettings {
                max_execution_seconds: 0,
                ..base.clone()
            },
        ),
        (
            "max_execution_seconds",
            RetroSettings {
                max_execution_seconds: OVER_EXEC_SECONDS,
                ..base.clone()
            },
        ),
        (
            "max_rows_to_read",
            RetroSettings {
                max_rows_to_read: 0,
                ..base.clone()
            },
        ),
        (
            "max_rows_to_read",
            RetroSettings {
                max_rows_to_read: OVER_ROWS_TO_READ,
                ..base.clone()
            },
        ),
    ] {
        assert!(
            matches!(validate_retro(&bad), Err(RetroError::Settings(found)) if found == name),
            "{name}"
        );
        assert!(check(bad)?.is_some_and(|text| text.contains(name)));
    }
    assert!(validate_retro(&base).is_ok());
    Ok(())
}


#[test]
fn a_bad_tenant_a_bad_window_and_a_bad_rule_are_refused_before_any_request() -> TestResult {
    let refused = |changed: RetroQuery| -> Result<RetroError, Box<dyn Error>> {
        let (outcome, seen) = run_script(vec![ok_text(&clean_reply())], &settings(), &changed)?;
        assert!(seen.is_empty());
        outcome.err().ok_or_else(|| "the run succeeded".into())
    };
    assert!(matches!(
        refused(RetroQuery {
            tenant: "-x".to_owned(),
            ..query()
        })?,
        RetroError::Tenant
    ));
    assert!(matches!(
        refused(RetroQuery {
            tenant: String::new(),
            ..query()
        })?,
        RetroError::Tenant
    ));
    assert!(matches!(refused(RetroQuery { end: START, ..query() })?, RetroError::Window));
    assert!(matches!(
        refused(RetroQuery {
            rule_text: "title: x".to_owned(),
            ..query()
        })?,
        RetroError::Rule(_)
    ));
    Ok(())
}


#[test]
fn the_window_is_bounded_in_days_and_in_range() -> TestResult {
    assert_eq!(window_epochs(START, END)?, (START_SECONDS, END_SECONDS));
    let week = START + time::Duration::days(MAX_RETRO_DAYS);
    assert!(window_epochs(START, week).is_ok());
    assert!(matches!(
        window_epochs(START, week + time::Duration::seconds(1)),
        Err(RetroError::WindowTooLong(MAX_RETRO_DAYS))
    ));
    assert!(matches!(window_epochs(END, START), Err(RetroError::Window)));
    assert!(matches!(window_epochs(BEFORE_EPOCH, START), Err(RetroError::Window)));
    assert!(matches!(window_epochs(START, FAR_FUTURE), Err(RetroError::Window)));
    Ok(())
}


#[test]
fn a_statement_failure_names_the_rule_error_without_text() -> TestResult {
    let error = retro_statement("not: a: rule", &mapping()?, &settings()).err().ok_or("compiled")?;
    assert!(matches!(error, RetroError::Rule(_)));
    assert_eq!(error.to_string(), "the rule cannot be compiled");
    Ok(())
}


#[test]
fn an_event_id_with_a_control_or_format_character_is_refused_alone() -> TestResult {
    assert!(id_allowed("evt-1"));
    assert!(id_allowed(""));
    assert!(!id_allowed("a\0b"));
    assert!(!id_allowed("a\nb"));
    assert!(!id_allowed("a\u{202e}b"));
    assert!(!id_allowed("a\u{200b}b"));
    assert!(id_allowed("caf\u{e9} \u{4e2d}"));
    let body = [
        row_json(1, "good", 1, "h", "u"),
        row_json(SECOND_ROW, "bad\u{7}id", 1, "h", "u"),
        row_json(THIRD_ROW, "rtl\u{202e}id", 1, "h", "u"),
        row_json(FOURTH_ROW, "also-good", 1, "h", "u"),
    ]
    .join("\n");
    let found = complete(body)?;
    assert_eq!(identities(&found), [identity(1, "good"), identity(FOURTH_ROW, "also-good")]);
    assert_eq!(found.refused, REFUSED);
    Ok(())
}


#[test]
fn an_empty_id_is_the_hash_alone_and_a_long_id_is_cut_with_its_length_kept() -> TestResult {
    assert_eq!(retro_identity("", &hash_of(1)), hash_of(1));
    let mut long = row_value(SECOND_ROW, &"x".repeat(ID_KEEP), 1, "h", "u");
    long.as_object_mut()
        .ok_or("object")?
        .insert("ret_id_chars".to_owned(), serde_json::json!(MEGABYTE));
    let found = complete(format!("{}\n{long}\n", row_json(1, "", 1, "h", "u")))?;
    let first = found.events.first().ok_or("none")?;
    let second = found.events.get(1).ok_or("one")?;
    assert_eq!(first.identity, hash_of(1));
    assert_eq!(second.identity, format!("{}:{}", "x".repeat(ID_CUT), hash_of(SECOND_ROW)));
    assert_eq!((first.id_chars, second.id_chars), (0, MEGABYTE as u32));
    Ok(())
}


#[test]
fn a_forged_duplicate_id_gets_another_identity_because_the_hash_differs() -> TestResult {
    let found = complete([row_json(1, "victim-id", 1, "h", "u"), row_json(SECOND_ROW, "victim-id", 1, "h", "u")].join("\n"))?;
    let both = identities(&found);
    assert_eq!(both.len(), REFUSED);
    assert_ne!(both.first(), both.get(1));
    Ok(())
}


#[test]
fn a_row_out_of_form_is_a_malformed_reply_and_an_invalid_id_is_refused_alone() -> TestResult {
    let row = |ms: &str, hash: &str, valid: u8| EventRow {
        ret_ms: ms.to_owned(),
        ret_hash: hash.to_owned(),
        ret_id: "e".to_owned(),
        ret_id_chars: 1,
        ret_id_valid: valid,
        ret_host: String::new(),
        ret_host_chars: 0,
        ret_user: String::new(),
        ret_user_chars: 0,
    };
    let good = hash_of(1);
    assert!(matches!(event_of(row("x", &good, 1)), Err(RetroError::MalformedReply)));
    assert!(matches!(event_of(row("1", "short", 1)), Err(RetroError::MalformedReply)));
    assert!(matches!(event_of(row("1", &good.replace('0', "G"), 1)), Err(RetroError::MalformedReply)));
    assert!(matches!(event_of(row("1", &good, BAD_FLAG)), Err(RetroError::MalformedReply)));
    assert!(matches!(event_of(row("1", &good, 0)), Ok(None)));
    assert!(matches!(
        event_of(row("1", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", 1)),
        Ok(Some(_))
    ));
    assert!(matches!(event_of(row("1", &good, 1)), Ok(Some(_))));
    let clamped = event_of(row(&i64::MAX.to_string(), &good, 1))?.ok_or("none")?;
    assert_eq!(clamped.event_time, "9999-12-31T23:59:59.999Z");
    Ok(())
}


#[test]
fn entities_are_cut_to_the_store_limit_and_a_bad_one_is_none() -> TestResult {
    assert_eq!(entity_of("host-1").as_deref(), Some("host-1"));
    assert_eq!(entity_of(""), None);
    assert_eq!(entity_of("a\u{202e}b"), None);
    let cut = entity_of(&"h".repeat(ENTITY_LIMIT + 1)).ok_or("none")?;
    assert_eq!(cut.chars().count(), ENTITY_LIMIT);
    let found = complete(format!("{}\n", row_json(1, "e", 1, "", "ok-user")))?;
    let event = found.events.first().ok_or("none")?;
    assert_eq!((event.host_name.as_deref(), event.user_name.as_deref()), (None, Some("ok-user")));
    Ok(())
}


#[test]
fn the_hash_input_is_length_prefixed_and_pinned_by_a_known_row() -> TestResult {
    assert_eq!(hash_part("a.b", HashKind::Text), "concat(toString(length(`a.b`)), ':', `a.b`)");
    assert_eq!(hash_part("n", HashKind::Number), "concat(toString(`n`), ';')");
    assert!(hash_part("arr", HashKind::TextArray).starts_with("concat(toString(length(`arr`)), '[', arrayStringConcat(arrayMap("));
    let expression = hash_expression();
    assert!(expression.starts_with("lower(hex(SHA256(concat(concat(toString(toUnixTimestamp64Milli(`@timestamp`)), ';'), "));
    let names: std::collections::BTreeSet<&str> = HASH_COLUMNS.iter().map(|(name, _)| *name).collect();
    assert_eq!(HASH_COLUMNS.len(), names.len());
    let known = |id: &str, message: &str| -> String {
        let text = |value: &str| format!("{}:{value}", value.len());
        let parts: Vec<String> = HASH_COLUMNS
            .iter()
            .map(|(name, kind)| match (*name, kind) {
                ("event.id", _) => text(id),
                ("message", _) => text(message),
                ("event.category", _) => format!("1[{}]", text("authentication")),
                ("event.type", _) => format!("1[{}]", text("denied")),
                ("host.os.type", _) => text("windows"),
                ("event.provider", _) => text("Microsoft-Windows-Security-Auditing"),
                ("event.code", _) => text("4625"),
                ("user.name", _) => text("root-admin"),
                (_, HashKind::Text) => text(""),
                (_, HashKind::Number) => "0;".to_owned(),
                (_, HashKind::TextArray) => "0[]".to_owned(),
            })
            .collect();
        format!("{:x}", Sha256::digest(format!("{KNOWN_MS};{}", parts.concat()).as_bytes()))
    };
    assert_eq!(known("e-1", "logon failed"), KNOWN_HASH);
    assert_ne!(known("e-1", "logon failed"), known("e-1", "logon faile"));
    assert_ne!(known("e-1", "x"), known("e-", "1:x"));
    Ok(())
}


#[test]
fn the_row_bound_fits_the_byte_cap_for_the_largest_row_count() -> TestResult {
    assert!((MAX_RETRO_ROWS as u64) * MAX_ROW_BYTES < MAX_RETRO_BYTES);
    let worst = row_json(
        1,
        &"\u{1}".repeat(ID_KEEP),
        1,
        &"\u{1}".repeat(ENTITY_LIMIT + 1),
        &"\u{1}".repeat(ENTITY_LIMIT + 1),
    );
    assert!((worst.len() as u64) < MAX_ROW_BYTES);
    assert!(retro_projection().contains("ret_user_chars"));
    Ok(())
}


#[test]
fn a_line_that_does_not_parse_is_a_run_error() -> TestResult {
    for text in ["not json\n", "{\"event.id\":1}\n", "{\"event.id\":\"a\",\"x\":1}\n", "\n"] {
        let outcome = read_ids(with_body(Box::new(Cursor::new(text.as_bytes().to_vec()))), ROWS);
        assert!(matches!(outcome, Err(RetroError::MalformedReply)), "{text}");
    }
    let found = absorb(RetroIds::default(), Err(io::Error::from(io::ErrorKind::InvalidData)), ROWS);
    assert!(matches!(found, Err(RetroError::MalformedReply)));
    let invalid = read_ids(with_body(Box::new(Cursor::new(BAD_UTF8.to_vec()))), ROWS);
    assert!(matches!(invalid, Err(RetroError::MalformedReply)));
    Ok(())
}


#[test]
fn a_body_over_the_byte_cap_is_refused_and_a_failing_body_keeps_no_text() -> TestResult {
    let big = vec![b'x'; OVER_BYTES];
    assert!(OVER_BYTES as u64 > MAX_RETRO_BYTES);
    let outcome = read_ids(with_body(Box::new(Cursor::new(big))), ROWS);
    assert!(matches!(outcome, Err(RetroError::TooManyBytes(MAX_RETRO_BYTES))));
    let failing = read_ids(with_body(Box::new(Failing)), ROWS).err().ok_or("read")?;
    assert!(matches!(failing, RetroError::Body(io::ErrorKind::ConnectionReset)));
    assert!(!format!("{failing} {failing:?}").contains("secret"));
    assert!(matches!(read_ids(with_body(Box::new(TimingOut)), ROWS), Err(RetroError::Timeout)));
    assert!(matches!(body_failure(&io::Error::from(io::ErrorKind::TimedOut)), RetroError::Timeout));
    assert!(matches!(
        read_changed(with_body(Box::new(Failing)), &settings()),
        Err(RetroError::Body(_))
    ));
    Ok(())
}


#[test]
fn an_oversized_settings_reply_is_counted_as_a_violation() -> TestResult {
    let big = "x".repeat(OVER_CHECK_BYTES);
    assert!(matches!(
        read_changed(with_body(Box::new(Cursor::new(big.into_bytes()))), &settings()),
        Err(RetroError::ReaderProfileChanged(_))
    ));
    Ok(())
}


struct Server {
    handle: JoinHandle<io::Result<Vec<String>>>,
    url: String,
}


fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [BYTE_ZERO; CHUNK];
    let mut expected = usize::MAX;
    let mut reads = 0;
    while received.len() < expected && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
        let lower = String::from_utf8_lossy(&received).to_lowercase();
        expected = lower.find(HEADER_END).map_or(usize::MAX, |end| {
            let length = lower
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            end + HEADER_END.len() + length
        });
        if count == 0 {
            expected = 0;
        }
    }
    Ok(String::from_utf8_lossy(&received).into_owned())
}


fn serve(replies: Vec<String>) -> Result<Server, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let handle = spawn(move || {
        replies.into_iter().try_fold(Vec::new(), |mut seen, text| {
            let (mut stream, _) = listener.accept()?;
            seen.push(read_request(&mut stream)?);
            stream.write_all(text.as_bytes())?;
            Ok(seen)
        })
    });
    Ok(Server { handle, url })
}


fn http(status: &str, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}


fn rig() -> Result<(TempDir, RetroSettings), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("password");
    fs::write(&path, format!("{PASSWORD}\n"))?;
    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))?;
    let found = RetroSettings {
        password_file: path,
        ..settings()
    };
    Ok((dir, found))
}


#[test]
fn the_real_sender_posts_the_statement_with_the_credentials_and_params() -> TestResult {
    let (_dir, base) = rig()?;
    let server = serve(vec![http("200 OK", "", &clean_reply()), http("200 OK", "", &id_lines(&["e1"]))])?;
    let found = RetroSettings {
        url: server.url.clone(),
        ..base
    };
    let outcome = run_retro(&found, &mapping()?, &query(), &|| Duration::ZERO)?;
    let seen = server.handle.join().map_err(|_| "server thread panicked")??;
    assert!(matches!(outcome, RetroOutcome::Complete(ids) if identities(&ids) == [identity(1, "e1")]));
    let read = seen.get(1).ok_or("no read")?;
    assert!(read.starts_with("POST /?readonly=2&http_write_exception_in_output_format=0&database=ostyr&param_tenant=tenant-a&"));
    assert!(read.contains(&format!("param_start={START_EPOCH}&param_end={END_EPOCH}&param_limit=4 HTTP/1.1")));
    assert!(read.to_lowercase().contains(&format!("x-clickhouse-key: {PASSWORD}").to_lowercase()));
    assert!(read.to_lowercase().contains("x-clickhouse-user: retro_reader"));
    assert!(read.contains("AS `ret_hash`"));
    assert!(!read.contains("tenant-a'"));
    Ok(())
}


#[test]
fn the_real_sender_maps_the_exception_header_and_a_refused_connection() -> TestResult {
    let (_dir, base) = rig()?;
    let server = serve(vec![http(
        "500 Internal Server Error",
        "X-ClickHouse-Exception-Code: 159\r\n",
        "Code: 159. secret",
    )])?;
    let found = RetroSettings {
        url: server.url.clone(),
        ..base.clone()
    };
    let error = run_retro(&found, &mapping()?, &query(), &|| Duration::ZERO).err().ok_or("succeeded")?;
    server.handle.join().map_err(|_| "server thread panicked")??;
    assert!(matches!(error, RetroError::Timeout));
    assert!(!error.to_string().contains("secret"));
    let request = RetroRequest {
        statement: "SELECT 1".to_owned(),
        settings: Vec::new(),
        params: Vec::new(),
        remaining: Duration::from_secs(1),
    };
    let held = TcpSocket::new_v4()?;
    held.bind("127.0.0.1:0".parse()?)?;
    let dead = RetroSettings {
        url: format!("http://127.0.0.1:{}", held.local_addr()?.port()),
        ..base
    };
    let agent = siem_ingest::clickhouse::new_agent(None, false)?;
    assert!(send_request(&agent, &dead, PASSWORD, &request).is_err());
    drop(held);
    Ok(())
}


#[test]
fn secrets_are_refused_before_any_connection() -> TestResult {
    let (dir, base) = rig()?;
    let run = |found: &RetroSettings| run_retro(found, &mapping()?, &query(), &|| Duration::ZERO).map_err(Box::<dyn Error>::from);
    let invalid = RetroSettings { max_rows: 0, ..base.clone() };
    assert!(matches!(
        run(&invalid).err().and_then(|error| error.downcast::<RetroError>().ok()).as_deref(),
        Some(RetroError::Settings("max_rows"))
    ));
    let missing = RetroSettings {
        password_file: dir.path().join("none"),
        ..base.clone()
    };
    assert!(matches!(
        run(&missing).err().and_then(|error| error.downcast::<RetroError>().ok()).as_deref(),
        Some(RetroError::Password(_))
    ));
    let other = dir.path().join("binary");
    fs::write(&other, BAD_UTF8)?;
    fs::set_permissions(&other, std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))?;
    let binary = RetroSettings {
        password_file: other,
        ..base.clone()
    };
    assert!(matches!(
        run(&binary).err().and_then(|error| error.downcast::<RetroError>().ok()).as_deref(),
        Some(RetroError::PasswordEncoding(_))
    ));
    let no_ca = RetroSettings {
        ca_file: Some(dir.path().join("missing.pem")),
        ..base.clone()
    };
    assert!(matches!(
        run(&no_ca).err().and_then(|error| error.downcast::<RetroError>().ok()).as_deref(),
        Some(RetroError::CaFile(_))
    ));
    let bad_pem = dir.path().join("bad.pem");
    fs::write(&bad_pem, "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")?;
    let garbage = RetroSettings {
        ca_file: Some(bad_pem),
        ..base
    };
    assert!(matches!(
        run(&garbage).err().and_then(|error| error.downcast::<RetroError>().ok()).as_deref(),
        Some(RetroError::Agent(_))
    ));
    Ok(())
}


const LONG_SEPARATOR_ID: usize = 70;


#[test]
fn an_event_id_with_a_line_separator_a_paragraph_separator_or_a_blank_letter_is_refused_alone() -> TestResult {
    assert!(!id_allowed("a\u{2028}b"));
    assert!(!id_allowed("a\u{2029}b"));
    assert!(!id_allowed(&"\u{2028}".repeat(LONG_SEPARATOR_ID)));
    INVISIBLE_CHARACTERS.iter().try_for_each(|blank| -> TestResult {
        assert!(!id_allowed(&format!("a{blank}b")));
        assert_eq!(entity_of(&format!("a{blank}b")), None);
        let found = complete([row_json(1, "good", 1, "h", "u"), row_json(SECOND_ROW, &format!("x{blank}y"), 1, "h", "u")].join("\n"))?;
        assert_eq!((found.events.len(), found.refused), (1, 1));
        Ok(())
    })?;
    let separators = [
        row_json(1, "good", 1, "h", "u"),
        row_json(SECOND_ROW, &"\u{2028}".repeat(LONG_SEPARATOR_ID), 1, "h", "u"),
    ]
    .join("\n");
    assert_eq!(complete(separators)?.refused, 1);
    let paragraph = complete(row_json(1, "p\u{2029}q", 1, "h", "u"))?;
    assert_eq!((paragraph.events.len(), paragraph.refused), (0, 1));
    assert!(id_allowed("a b"));
    assert!(id_allowed("caf\u{e9}"));
    Ok(())
}


#[test]
fn the_hashed_columns_are_the_schema_columns_without_tenant_tier_and_time() -> TestResult {
    let excluded = ["tenant", "tenant_tier", "@timestamp"];
    let schema: Vec<String> = default_columns()
        .into_iter()
        .map(|column| column.name)
        .filter(|name| !excluded.contains(&name.as_str()))
        .collect();
    let hashed: Vec<String> = HASH_COLUMNS.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert_eq!(hashed, schema);
    Ok(())
}
