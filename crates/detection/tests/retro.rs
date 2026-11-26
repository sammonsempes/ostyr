#![cfg(unix)]

#[path = "retro/types.rs"]
mod types;


use detection::error::RetroError;
use detection::retro::{
    absorb, body_failure, check_refusal, fetch_with, id_allowed, read_changed, read_ids, refusal, retro_run, retro_statement, run_retro,
    send_request, validate_retro, window_epochs, RetroIds, RetroOutcome, RetroQuery, RetroReply, RetroRequest, RetroSettings, MAX_RETRO_BYTES,
    MAX_RETRO_DAYS, MAX_RETRO_ROWS,
};
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::pins;
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


const OVER_BYTES: usize = 4_200_000;


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


const ID_LIMIT: usize = 128;


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


fn id_lines(ids: &[&str]) -> String {
    ids.iter().map(|id| format!("{{\"event.id\":{}}}\n", serde_json::json!(id))).collect()
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
    assert_eq!(
        outcome?,
        RetroOutcome::Complete(RetroIds {
            ids: vec!["e1".to_owned(), "e2".to_owned()],
            refused: 0,
            rows: IDS_READ
        })
    );
    assert_eq!(seen.len(), IDS_READ);
    let check = seen.first().ok_or("no check")?;
    assert!(check.statement.contains("FROM `system`.`settings` WHERE `changed` SETTINGS "));
    let read = seen.get(1).ok_or("no read")?;
    assert!(read.statement.starts_with("SELECT `event.id` FROM `events` WHERE "));
    assert!(read
        .statement
        .contains("`tenant` = {tenant:String} AND `@timestamp` >= toDateTime({start:UInt32}, 'UTC')"));
    assert!(read
        .statement
        .contains("ORDER BY `@timestamp`, `event.id` LIMIT {limit:UInt64} SETTINGS max_execution_time = 30, max_rows_to_read = 1000000, "));
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
    assert!(matches!(&outcome, RetroOutcome::RowCap { found, cap } if *cap == ROWS && found.ids == ["e1", "e2", "e3"] && found.rows == ROWS + 1));
    Ok(())
}


#[test]
fn exactly_the_cap_is_complete() -> TestResult {
    let (outcome, _) = run_script(
        vec![ok_text(&clean_reply()), ok_text(&id_lines(&["e1", "e2", "e3"]))],
        &settings(),
        &query(),
    )?;
    assert!(matches!(outcome?, RetroOutcome::Complete(found) if found.ids.len() == ROWS));
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
fn an_event_id_outside_the_grammar_is_refused_alone() -> TestResult {
    assert!(id_allowed("evt-1"));
    assert!(!id_allowed(""));
    assert!(!id_allowed(&"a".repeat(ID_LIMIT + 1)));
    assert!(id_allowed(&"a".repeat(ID_LIMIT)));
    assert!(!id_allowed("a\0b"));
    assert!(!id_allowed("a\nb"));
    let body = id_lines(&["good", "", "bad\u{7}id", "also-good"]);
    let outcome = read_ids(with_body(Box::new(Cursor::new(body.into_bytes()))), WIDE_CAP)?;
    assert!(matches!(&outcome, RetroOutcome::Complete(found) if found.ids == ["good", "also-good"] && found.refused == REFUSED));
    Ok(())
}


#[test]
fn a_line_that_does_not_parse_is_a_run_error() -> TestResult {
    for text in ["not json\n", "{\"event.id\":1}\n", "{\"event.id\":\"a\",\"x\":1}\n", "\n"] {
        let outcome = read_ids(with_body(Box::new(Cursor::new(text.as_bytes().to_vec()))), ROWS);
        assert!(matches!(outcome, Err(RetroError::MalformedReply)), "{text}");
    }
    let found = absorb(RetroIds::default(), Err(io::Error::from(io::ErrorKind::InvalidData)), ROWS);
    assert!(matches!(found, Err(RetroError::Body(io::ErrorKind::InvalidData))));
    let invalid = read_ids(with_body(Box::new(Cursor::new(BAD_UTF8.to_vec()))), ROWS);
    assert!(matches!(invalid, Err(RetroError::Body(io::ErrorKind::InvalidData))));
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
    assert!(matches!(outcome, RetroOutcome::Complete(ids) if ids.ids == vec!["e1"]));
    let read = seen.get(1).ok_or("no read")?;
    assert!(read.starts_with("POST /?readonly=2&http_write_exception_in_output_format=0&database=ostyr&param_tenant=tenant-a&"));
    assert!(read.contains(&format!("param_start={START_EPOCH}&param_end={END_EPOCH}&param_limit=4 HTTP/1.1")));
    assert!(read.to_lowercase().contains(&format!("x-clickhouse-key: {PASSWORD}").to_lowercase()));
    assert!(read.to_lowercase().contains("x-clickhouse-user: retro_reader"));
    assert!(read.contains("SELECT `event.id` FROM `events` WHERE "));
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
    let held = TcpListener::bind("127.0.0.1:0")?;
    let dead = RetroSettings {
        url: format!("http://127.0.0.1:{}", held.local_addr()?.port()),
        ..base
    };
    drop(held);
    let agent = siem_ingest::clickhouse::new_agent(None, false)?;
    assert!(send_request(&agent, &dead, PASSWORD, &request).is_err());
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
