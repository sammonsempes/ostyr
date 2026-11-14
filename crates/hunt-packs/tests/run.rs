mod common;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use hunt_packs::model::Source;
use hunt_packs::run::{count_statement, parse_count, read_count, run_pack, server_settings, window_text, HuntOutcome, RunError, MAX_COUNT_BYTES};
use metric_alerts::fetch::agent_for;
use sample::{pack, param, sent_params, settings, NOW, PASSWORD};
use siem_ingest::error::InsertClass;
use std::io::{self, Read};
use std::net::TcpListener;
use std::time::Duration;
use stub::reply;


const COUNT: u64 = 42;


const SEVEN: u64 = 7;


const BODIES: usize = 4;


const HOSTILE: usize = 7;


const SERVER_SETTINGS: usize = 6;


const OK: &str = "200 OK";


const LONG: Duration = Duration::from_secs(60);


const HUGE: usize = 10_485_760;


const HUNDRED: usize = 100;


const LAST_SECOND_OF_9999: u64 = 253_402_300_799;


const SECRET: &str = "SECRET-SERVER-TEXT";


const PARSE_CODE: &str = "X-ClickHouse-Exception-Code: 27\r\n";


const MAX_ROWS_LIMIT: &str = "1000";


struct Endless {
    served: usize,
}


impl Read for Endless {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        buffer.fill(b'7');
        self.served += buffer.len();
        Ok(buffer.len())
    }
}


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }
}


fn run(port: u16, tenant: &str, remaining: Duration) -> Result<HuntOutcome, RunError> {
    let config = settings(port);
    let agent = agent_for(&config).map_err(|_| RunError::Window)?;
    run_pack(&agent, &config, PASSWORD, &pack(), tenant, NOW, remaining)
}


fn served(status: &'static str, extra: &'static str, body: Vec<u8>) -> Result<(u16, std::thread::JoinHandle<io::Result<String>>), io::Error> {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    Ok((port, reply(bound, status, extra, body)))
}


fn run_against(
    status: &'static str,
    extra: &'static str,
    body: Vec<u8>,
) -> Result<(Result<HuntOutcome, RunError>, String), Box<dyn std::error::Error>> {
    let (port, server) = served(status, extra, body)?;
    let outcome = run(port, "acme", LONG);
    let seen = server.join().map_err(|_| "server thread")??;
    Ok((outcome, seen))
}


fn refused_without_io(
    change: impl FnOnce(&mut hunt_packs::model::HuntPack),
    tenant: &str,
    remaining: Duration,
) -> Result<RunError, Box<dyn std::error::Error>> {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    bound.set_nonblocking(true)?;
    let config = settings(bound.local_addr()?.port());
    let agent = agent_for(&config)?;
    let mut candidate = pack();
    change(&mut candidate);
    let error = run_pack(&agent, &config, PASSWORD, &candidate, tenant, NOW, remaining)
        .err()
        .ok_or("run accepted")?;
    let connection = bound.accept();
    assert_eq!(
        connection.err().map(|found| found.kind()),
        Some(io::ErrorKind::WouldBlock),
        "a connection was made"
    );
    Ok(error)
}


#[test]
fn count_is_read_and_compared_to_the_baseline() -> TestResult {
    let (outcome, seen) = run_against(OK, "", b"42\n".to_vec())?;
    assert_eq!(
        outcome?,
        HuntOutcome {
            matches: COUNT,
            finding: true
        }
    );
    assert!(seen.starts_with("POST /?"), "{seen}");
    assert!(seen.contains("SELECT count() FROM ("), "{seen}");
    assert!(seen.contains(" FORMAT TabSeparated"), "{seen}");
    assert!(!seen.contains(PASSWORD) || seen.to_lowercase().contains("x-clickhouse-key"), "{seen}");
    let (zero, _) = run_against(OK, "", b"0\n".to_vec())?;
    assert_eq!(zero?, HuntOutcome { matches: 0, finding: false });
    Ok(())
}


#[test]
fn sent_url_holds_every_setting_and_the_callers_tenant() -> TestResult {
    let (outcome, seen) = run_against(OK, "", b"1".to_vec())?;
    assert_eq!(outcome?.matches, 1);
    let params = sent_params(&seen)?;
    let expected = [
        ("readonly", "1"),
        ("max_execution_time", "10"),
        ("max_rows_to_read", MAX_ROWS_LIMIT),
        ("max_bytes_to_read", "1000000"),
        ("max_result_rows", "1"),
        ("result_overflow_mode", "throw"),
        ("param_tenant", "acme"),
        ("param_window_end", "2023-11-14 22:13:20.000"),
        ("param_window_start", "2023-11-13 22:13:20.000"),
    ];
    expected
        .iter()
        .for_each(|(name, _)| assert_eq!(params.iter().filter(|(found, _)| found == name).count(), 1, "{name}: {params:?}"));
    expected.iter().try_for_each(|(name, value)| {
        assert_eq!(&param(&seen, name)?, value);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(params.len(), expected.len(), "{params:?}");
    assert!(seen.to_lowercase().contains("x-clickhouse-user: ostyr"), "{seen}");
    assert!(
        seen.to_lowercase().contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase())),
        "{seen}"
    );
    Ok(())
}


#[test]
fn malformed_bodies_are_refused() -> TestResult {
    let bodies: [Vec<u8>; BODIES] = [vec![b'7'; HUNDRED], b"abc".to_vec(), b"-1".to_vec(), Vec::new()];
    bodies.into_iter().try_for_each(|body| {
        let (outcome, _) = run_against(OK, "", body)?;
        assert!(matches!(outcome, Err(RunError::Malformed)), "{outcome:?}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let hostile: [&[u8]; HOSTILE] = [b"+5", b"4\n5", b"1\n\n", b"1 ", b"\xff", b"99999999999999999999", b"\n"];
    hostile
        .iter()
        .for_each(|body| assert!(matches!(parse_count(body), Err(RunError::Malformed)), "{body:?}"));
    assert_eq!(parse_count(b"7")?, SEVEN);
    assert_eq!(parse_count(b"18446744073709551615\n")?, u64::MAX);
    Ok(())
}


#[test]
fn a_huge_reply_is_read_only_up_to_the_bound() -> TestResult {
    let mut endless = Endless { served: 0 };
    assert!(matches!(read_count(&mut endless), Err(RunError::Malformed)));
    assert_eq!(endless.served as u64, MAX_COUNT_BYTES + 1);
    assert!(matches!(read_count(Broken), Err(RunError::Body(_))));
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    let _server = reply(bound, OK, "", vec![b'7'; HUGE]);
    let outcome = run(port, "acme", LONG);
    assert!(matches!(outcome, Err(RunError::Malformed)), "{outcome:?}");
    Ok(())
}


#[test]
fn server_failures_keep_only_the_class() -> TestResult {
    let cases = [
        ("500 Internal Server Error", PARSE_CODE, InsertClass::ParseError),
        ("504 Gateway Timeout", "", InsertClass::Timeout),
        ("401 Unauthorized", "", InsertClass::Unauthorized),
        ("503 Service Unavailable", "", InsertClass::Unavailable),
    ];
    cases.into_iter().try_for_each(|(status, extra, class)| {
        let (outcome, _) = run_against(status, extra, SECRET.as_bytes().to_vec())?;
        let error = outcome.err().ok_or("accepted")?;
        let text = format!("{error} {error:?}");
        assert!(matches!(&error, RunError::Failed(found) if *found == class), "{text}");
        assert!(!text.contains(SECRET) && !text.contains(PASSWORD) && !text.contains("SELECT"), "{text}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_dead_server_is_unavailable() -> TestResult {
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let outcome = run(port, "acme", LONG);
    assert!(matches!(outcome, Err(RunError::Failed(InsertClass::Unavailable))), "{outcome:?}");
    Ok(())
}


#[test]
fn refusals_happen_before_any_connection() -> TestResult {
    let osquery = refused_without_io(|candidate| candidate.source = Source::Osquery, "acme", LONG)?;
    assert!(matches!(osquery, RunError::UnsupportedSource));
    let tenant = refused_without_io(|_| {}, "-x", LONG)?;
    assert!(matches!(tenant, RunError::Tenant(_)));
    let empty_tenant = refused_without_io(|_| {}, "", LONG)?;
    assert!(matches!(empty_tenant, RunError::Tenant(_)));
    let bytes = refused_without_io(|candidate| candidate.cost.max_bytes_read = None, "acme", LONG)?;
    assert!(matches!(bytes, RunError::NoByteLimit));
    let window = refused_without_io(|candidate| candidate.window_seconds = NOW + 1, "acme", LONG)?;
    assert!(matches!(window, RunError::Window));
    let spent = refused_without_io(|_| {}, "acme", Duration::ZERO)?;
    assert!(matches!(spent, RunError::Failed(InsertClass::Timeout)));
    Ok(())
}


#[test]
fn window_arithmetic_is_checked() -> TestResult {
    assert_eq!(window_text(0)?, "1970-01-01 00:00:00.000");
    assert_eq!(window_text(LAST_SECOND_OF_9999)?, "9999-12-31 23:59:59.000");
    assert!(matches!(window_text(LAST_SECOND_OF_9999 + 1), Err(RunError::Window)));
    assert!(matches!(window_text(u64::MAX), Err(RunError::Window)));
    assert!(matches!(window_text(i64::MAX as u64), Err(RunError::Window)));
    Ok(())
}


#[test]
fn statement_and_settings() -> TestResult {
    assert_eq!(
        count_statement("SELECT 1 -- x\n;\n"),
        "SELECT count() FROM (\nSELECT 1 -- x\n) FORMAT TabSeparated"
    );
    let mut candidate = pack();
    assert_eq!(server_settings(&candidate)?.len(), SERVER_SETTINGS);
    candidate.cost.max_bytes_read = None;
    assert!(matches!(server_settings(&candidate), Err(RunError::NoByteLimit)));
    let texts = [RunError::UnsupportedSource, RunError::Window, RunError::NoByteLimit, RunError::Malformed];
    texts.iter().for_each(|error| assert!(!error.to_string().is_empty()));
    Ok(())
}
