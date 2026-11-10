#[path = "common/stub.rs"]
mod stub;
#[path = "common/types.rs"]
mod types;


use intel_feeds::config::{validate_clickhouse, ClickhouseConfig, ClickhouseError};
use intel_feeds::limits::{MAX_ROWS_PER_BATCH, MAX_TIMEOUT_MS, MAX_USER_BYTES};
use intel_feeds::load::{agent_for, load_iocs, post, schema_statements, summarise, BatchFailure, LoadError, LoadOutcome};
use intel_feeds::model::{Ioc, IocType, Source, Tags, Tlp};
use intel_feeds::store::{insert_plan, settings_for};
use serde_json::Value;
use siem_ingest::clickhouse::MAX_CA_BYTES;
use siem_ingest::error::InsertClass;
use std::cell::Cell;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stub::{serve, stall};
use tempfile::{tempdir, TempDir};
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const PASSWORD: &str = "TRACEPW-5b2e8d40";


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


const SCHEMA_REQUESTS: usize = 3;


const STALL_TIMEOUT_MS: u64 = 100;


const LONG_TIMEOUT_MS: u64 = 60_000;


const ONE_HOUR: Duration = Duration::from_secs(3600);


const SPILL: usize = 1;


const THREE: usize = 3;


const TWO: usize = 2;


const TABLE_AND_DICTIONARY: usize = 2;


const CONFIDENCE: u8 = 70;


const PASSWORD_OVERSIZE: usize = 2048;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const LONG_AGO: OffsetDateTime = datetime!(2020-01-01 00:00:00 UTC);


struct Rig {
    dir: TempDir,
    config: ClickhouseConfig,
    listener: TcpListener,
}


fn rig(timeout_ms: u64) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    fs::write(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let config = ClickhouseConfig {
        url: format!("http://127.0.0.1:{port}"),
        user: "ostyr".to_owned(),
        password_file: dir.path().join("password"),
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "iocs".to_owned(),
        dictionary: "ioc_trie".to_owned(),
        timeout_ms,
        tenant: "tenant-a".to_owned(),
    };
    Ok(Rig { dir, config, listener })
}


fn ioc(value: &str) -> Ioc {
    Ioc {
        ioc_type: IocType::Domain,
        value: value.to_owned(),
        sources: vec![Source {
            feed: "feed".to_owned(),
            version: "v1".to_owned(),
        }],
        first_seen: NOW,
        last_seen: NOW,
        confidence: CONFIDENCE,
        tlp: Tlp::Amber,
        expires_at: None,
        tags: Tags::default(),
    }
}


fn iocs(count: usize) -> Vec<Ioc> {
    (0..count).map(|number| ioc(&format!("host{number}.example"))).collect()
}


fn idle() -> Duration {
    Duration::ZERO
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


fn joined<Output>(handle: std::thread::JoinHandle<io::Result<Output>>) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


#[test]
fn schema_then_batches_in_order_with_the_key_in_a_header_only() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec![OK; SCHEMA_REQUESTS + 1]);
    let outcome = load_iocs(&rig.config, &iocs(THREE), &[], NOW, &idle)?;
    assert_eq!(outcome.rows_per_batch, vec![THREE]);
    assert_eq!(outcome.failure, None);
    let seen = joined(server)?;
    let first = seen.first().ok_or("no request")?;
    assert!(first.contains("CREATE DATABASE IF NOT EXISTS `ostyr`"));
    assert!(seen.get(1).ok_or("no table")?.contains("CREATE TABLE IF NOT EXISTS `ostyr`.`iocs`"));
    assert!(seen
        .get(TABLE_AND_DICTIONARY)
        .ok_or("no dictionary")?
        .contains("CREATE DICTIONARY IF NOT EXISTS `ostyr`.`ioc_trie`"));
    let insert = seen.get(SCHEMA_REQUESTS).ok_or("no insert")?;
    let head = insert.lines().next().ok_or("no head")?;
    assert!(head.starts_with("POST /?query=INSERT"), "{head}");
    assert!(head.contains("FORMAT"));
    assert!(!head.contains(PASSWORD));
    assert!(seen
        .iter()
        .all(|request| request.lines().next().is_some_and(|line| !line.contains(PASSWORD))));
    assert!(seen
        .iter()
        .all(|request| request.to_lowercase().contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase()))));
    assert!(insert.contains("\"tenant\":\"tenant-a\""));
    assert_eq!(insert.matches("\"ioc_type\":\"domain\"").count(), THREE);
    Ok(())
}


#[test]
fn a_failed_second_batch_stops_the_load_and_reports_the_first_as_stored() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let mut statuses = vec![OK; SCHEMA_REQUESTS + 1];
    statuses.push(SERVER_ERROR);
    let server = serve(rig.listener.try_clone()?, statuses);
    let all = iocs(MAX_ROWS_PER_BATCH + SPILL);
    let plan = insert_plan(&all, &settings_for("tenant-a", &[]), NOW);
    let first = plan.batches.first().ok_or("no first batch")?.rows;
    let second = plan.batches.get(1).ok_or("no second batch")?.rows;
    let outcome = load_iocs(&rig.config, &all, &[], NOW, &idle)?;
    assert_eq!(outcome.rows_per_batch, vec![first]);
    assert_eq!(
        outcome.failure,
        Some(BatchFailure {
            index: 1,
            rows: second,
            class: InsertClass::Unavailable
        })
    );
    assert_eq!(joined(server)?.len(), SCHEMA_REQUESTS + TWO);
    let summary = summarise(&Ok(outcome));
    assert_eq!(summary.clickhouse_rows_sent, first);
    assert_eq!(summary.clickhouse_batches_stored, 1);
    assert_eq!(summary.clickhouse_batches_failed, plan.batches.len() - 1);
    assert_eq!(summary.failed_batch, Some(1));
    assert!(summary.error.is_some_and(|text| text.contains("Unavailable")));
    Ok(())
}


#[test]
fn a_redirect_is_a_refusal_and_never_followed() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let mut statuses = vec![OK; SCHEMA_REQUESTS];
    statuses.push("302 Found");
    let server = serve(rig.listener.try_clone()?, statuses);
    let outcome = load_iocs(&rig.config, &iocs(1), &[], NOW, &idle)?;
    assert_eq!(outcome.failure.map(|failure| failure.class), Some(InsertClass::Rejected));
    assert_eq!(joined(server)?.len(), SCHEMA_REQUESTS + 1);
    Ok(())
}


#[test]
fn a_refused_schema_statement_is_an_error() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec!["401 Unauthorized"]);
    let failed = load_iocs(&rig.config, &iocs(1), &[], NOW, &idle);
    assert!(matches!(failed, Err(LoadError::Schema(InsertClass::Unauthorized))));
    assert_eq!(joined(server)?.len(), 1);
    Ok(())
}


#[test]
fn a_server_that_never_answers_hits_the_deadline() -> TestResult {
    let rig = rig(STALL_TIMEOUT_MS)?;
    let (release, held) = channel();
    let server = stall(rig.listener.try_clone()?, held);
    let failed = load_iocs(&rig.config, &iocs(1), &[], NOW, &idle);
    release.send(())?;
    joined(server)?;
    assert!(matches!(failed, Err(LoadError::Schema(InsertClass::Timeout))));
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let rig = rig(STALL_TIMEOUT_MS)?;
    let spent = || ONE_HOUR;
    assert!(matches!(
        load_iocs(&rig.config, &iocs(1), &[], NOW, &spent),
        Err(LoadError::Schema(InsertClass::Timeout))
    ));
    assert!(untouched(&rig.listener)?);
    let calls = Cell::new(0);
    let late = || {
        calls.set(calls.get() + 1);
        if calls.get() > SCHEMA_REQUESTS {
            ONE_HOUR
        } else {
            Duration::ZERO
        }
    };
    let server = serve(rig.listener.try_clone()?, vec![OK; SCHEMA_REQUESTS]);
    rig.listener.set_nonblocking(false)?;
    let outcome = load_iocs(&rig.config, &iocs(1), &[], NOW, &late)?;
    assert_eq!(outcome.rows_per_batch, Vec::<usize>::new());
    assert_eq!(outcome.failure.map(|failure| failure.class), Some(InsertClass::Timeout));
    assert_eq!(joined(server)?.len(), SCHEMA_REQUESTS);
    Ok(())
}


#[test]
fn a_lookalike_host_is_refused_before_any_connection() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    let port = rig.listener.local_addr()?.port();
    rig.config.url = format!("http://localhost.evil.test:{port}");
    let failed = load_iocs(&rig.config, &iocs(TWO), &[], NOW, &idle);
    assert!(matches!(failed, Err(LoadError::Settings(ClickhouseError::Url(_)))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_tenant_core_pg_refuses_is_refused_before_any_io() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    rig.config.tenant = "-x".to_owned();
    fs::remove_file(&rig.config.password_file)?;
    let failed = load_iocs(&rig.config, &iocs(TWO), &[], NOW, &idle);
    assert!(matches!(failed, Err(LoadError::Settings(ClickhouseError::Tenant(_)))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn identifiers_with_a_quote_or_a_semicolon_are_refused() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    ["io`cs", "iocs;drop", "", "1iocs", "a b"].iter().try_for_each(|name| -> TestResult {
        [0, 1, TWO].iter().try_for_each(|which| -> TestResult {
            let mut config = rig.config.clone();
            match which {
                0 => config.database = (*name).to_owned(),
                1 => config.table = (*name).to_owned(),
                _ => config.dictionary = (*name).to_owned(),
            }
            assert!(matches!(validate_clickhouse(&config), Err(ClickhouseError::Identifier(_))));
            assert!(load_iocs(&config, &iocs(1), &[], NOW, &idle).is_err());
            Ok(())
        })
    })?;
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn user_and_timeout_are_bounded() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    validate_clickhouse(&rig.config)?;
    let with_user = |user: &str| ClickhouseConfig {
        user: user.to_owned(),
        ..rig.config.clone()
    };
    ["", "a\nb", "a b", &"u".repeat(MAX_USER_BYTES + 1)]
        .iter()
        .for_each(|user| assert!(matches!(validate_clickhouse(&with_user(user)), Err(ClickhouseError::User))));
    [0, MAX_TIMEOUT_MS + 1].iter().for_each(|timeout_ms| {
        let config = ClickhouseConfig {
            timeout_ms: *timeout_ms,
            ..rig.config.clone()
        };
        assert!(matches!(validate_clickhouse(&config), Err(ClickhouseError::Timeout)));
    });
    Ok(())
}


#[test]
fn a_value_with_a_newline_or_a_nul_stays_one_json_row() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec![OK; SCHEMA_REQUESTS + 1]);
    let hostile = vec![ioc("a\nb\u{0}c"), ioc("x\r\ny")];
    load_iocs(&rig.config, &hostile, &[], NOW, &idle)?;
    let seen = joined(server)?;
    let insert = seen.get(SCHEMA_REQUESTS).ok_or("no insert")?;
    let body = insert.split("\r\n\r\n").nth(1).ok_or("no body")?;
    assert_eq!(body.lines().count(), TWO);
    let values: Vec<Value> = body.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
    assert_eq!(values.first().and_then(|row| row["value"].as_str()), Some("a\nb\u{0}c"));
    Ok(())
}


#[test]
fn the_password_file_is_checked_when_read() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let reject = |config: &ClickhouseConfig| matches!(load_iocs(config, &iocs(1), &[], NOW, &idle), Err(LoadError::Password(_)));
    fs::write(&rig.config.password_file, vec![b'p'; PASSWORD_OVERSIZE])?;
    assert!(reject(&rig.config));
    fs::write(&rig.config.password_file, "\n")?;
    assert!(reject(&rig.config));
    let fifo = rig.dir.path().join("fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    let on_fifo = ClickhouseConfig {
        password_file: fifo,
        ..rig.config.clone()
    };
    assert!(reject(&on_fifo));
    fs::write(&rig.config.password_file, NOT_UTF8)?;
    assert!(matches!(
        load_iocs(&rig.config, &iocs(1), &[], NOW, &idle),
        Err(LoadError::PasswordEncoding(_))
    ));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn the_ca_file_is_bounded_regular_and_parsed() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let with_ca = |path: &Path| ClickhouseConfig {
        ca_file: Some(path.to_path_buf()),
        ..rig.config.clone()
    };
    let big = rig.dir.path().join("big.pem");
    fs::write(&big, vec![b'a'; MAX_CA_BYTES as usize + 1])?;
    assert!(matches!(agent_for(&with_ca(&big)), Err(LoadError::CaFile(_))));
    let fifo = rig.dir.path().join("fifo.pem");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(agent_for(&with_ca(&fifo)), Err(LoadError::CaFile(_))));
    let missing = rig.dir.path().join("missing.pem");
    assert!(matches!(agent_for(&with_ca(&missing)), Err(LoadError::CaFile(_))));
    let junk = rig.dir.path().join("junk.pem");
    fs::write(&junk, "-----BEGIN CERTIFICATE-----\nnot base64 !\n-----END CERTIFICATE-----\n")?;
    assert!(matches!(agent_for(&with_ca(&junk)), Err(LoadError::Agent(_))));
    assert!(agent_for(&rig.config).is_ok());
    assert!(matches!(load_iocs(&with_ca(&junk), &iocs(1), &[], NOW, &idle), Err(LoadError::Agent(_))));
    Ok(())
}


#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn a_trace_subscriber_never_sees_the_key() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec![OK; SCHEMA_REQUESTS + 1]);
    let expired = ioc("old.example");
    let old = Ioc {
        expires_at: Some(LONG_AGO),
        ..expired
    };
    tracing::subscriber::with_default(subscriber, || load_iocs(&rig.config, &[old, ioc("new.example")], &[], NOW, &idle))?;
    joined(server)?;
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    assert!(tracing::level_filters::STATIC_MAX_LEVEL <= tracing::level_filters::LevelFilter::DEBUG);
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("left out"), "{logged}");
    assert!(!logged.contains(PASSWORD));
    Ok(())
}


#[test]
fn schema_statements_are_idempotent_and_post_without_a_statement_sends_the_body() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    assert!(schema_statements(&rig.config)?.iter().all(|text| text.contains("IF NOT EXISTS")));
    let bad = ClickhouseConfig {
        table: "a;b".to_owned(),
        ..rig.config.clone()
    };
    assert!(schema_statements(&bad).is_err());
    let agent = agent_for(&rig.config)?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    assert_eq!(post(&agent, &rig.config, PASSWORD, None, "SELECT 1".to_owned(), ONE_HOUR), None);
    assert!(joined(server)?.first().is_some_and(|request| request.ends_with("SELECT 1")));
    Ok(())
}


#[test]
fn an_unreachable_server_is_unavailable_and_an_error_is_summarised() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let agent = agent_for(&rig.config)?;
    let free = TcpListener::bind("127.0.0.1:0")?;
    let port = free.local_addr()?.port();
    drop(free);
    let config = ClickhouseConfig {
        url: format!("http://127.0.0.1:{port}"),
        ..rig.config.clone()
    };
    assert_eq!(
        post(&agent, &config, PASSWORD, None, String::new(), ONE_HOUR),
        Some(InsertClass::Unavailable)
    );
    let summary = summarise(&Err(LoadError::Schema(InsertClass::Timeout)));
    assert_eq!(summary.clickhouse_rows_sent, 0);
    assert!(summary.error.is_some_and(|text| text.contains("Timeout")));
    let clean = summarise(&Ok(LoadOutcome::default()));
    assert_eq!(clean.error, None);
    Ok(())
}
