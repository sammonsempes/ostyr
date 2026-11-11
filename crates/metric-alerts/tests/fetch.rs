mod common;
#[path = "common/hold.rs"]
mod hold;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use hold::{endless, half_reply, stall};
use metric_alerts::fetch::{
    agent_for, class_text, default_timeout_ms, escape_param, fetch_points, load_fetch_settings, parse_line, parse_points, read_key, read_points,
    validate_fetch_settings, FetchError, FetchSettings, LineFault, LineFaults, DEFAULT_TIMEOUT_MS, MAX_CA_BYTES, MAX_FETCH_BYTES, MAX_FETCH_POINTS,
    MAX_TIMEOUT_MS, MAX_USER_BYTES,
};
use metric_alerts::model::{Condition, Direction, Rule, Severity};
use metric_alerts::query::{parse_tenant_id, rule_sql, MetricQuery};
use metric_alerts::types::FetchResult;
use siem_ingest::error::InsertClass;
use siem_schema::metrics::MetricsRetention;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::net::TcpListener;
use std::sync::mpsc::channel;
use std::time::Duration;
use stub::reply;
use tempfile::tempdir;


const NOW: u64 = 1_000_000_000;


const OK: &str = "200 OK";


const PASSWORD: &str = "FETCHPW-91c3";


const HOSTILE_MOUNT: &str = "/\nx' OR 1=1 --";


const HOSTILE_PATH: &str = "C:\\tmp\tdir\r\0}";


const DEADLINE: Duration = Duration::from_millis(200);


const LONG: Duration = Duration::from_secs(60);


const THREE: usize = 3;


const TWO: usize = 2;


const CLASS_COUNT: usize = 5;


const HOLD_FOR: u64 = 300;


const CLOSE_AFTER: u64 = 60;


const HEX_RADIX: u32 = 16;


const ESCAPE_DIGITS: usize = 2;


const FIRST: f64 = 1.5;


const SECOND: f64 = -2.0;


const THOUSAND: f64 = 1000.0;


const SINGLE: f64 = 2.5;


const TS_SECOND: u64 = 2;


const TS_THIRD: u64 = 3;


const BAD_BYTES: [u8; 2] = [0xff, 0xfe];


const PARSE_CODE: &str = "X-ClickHouse-Exception-Code: 27\r\n";


const THRESHOLD: f64 = 90.0;


fn settings(port: u16) -> FetchSettings {
    FetchSettings {
        url: format!("http://127.0.0.1:{port}"),
        user: "ostyr".to_string(),
        password_file: "unused".into(),
        ca_file: None,
        timeout_ms: DEFAULT_TIMEOUT_MS,
    }
}


fn query() -> Result<MetricQuery, Box<dyn Error>> {
    let selector: BTreeMap<String, String> = [("mount", HOSTILE_MOUNT), ("path", HOSTILE_PATH)]
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let rule = Rule {
        id: "r".to_string(),
        metric: "disk.used".to_string(),
        selector,
        condition: Condition::Threshold {
            direction: Direction::Above,
            threshold: THRESHOLD,
            clear: None,
        },
        hold_for: HOLD_FOR,
        close_after: CLOSE_AFTER,
        severity: Severity::High,
        labels: BTreeMap::new(),
        runbook: "https://r.example.org".to_string(),
    };
    Ok(rule_sql(&rule, &parse_tenant_id("acme")?, NOW, &MetricsRetention::default())?)
}


fn percent_decode(text: &str) -> Result<String, Box<dyn Error>> {
    let mut parts = text.split('%');
    let head = parts.next().unwrap_or("").as_bytes().to_vec();
    let bytes = parts.try_fold(head, |mut decoded, part| {
        decoded.push(u8::from_str_radix(part.get(..ESCAPE_DIGITS).ok_or("short escape")?, HEX_RADIX)?);
        decoded.extend_from_slice(part.get(ESCAPE_DIGITS..).unwrap_or("").as_bytes());
        Ok::<_, Box<dyn Error>>(decoded)
    })?;
    Ok(String::from_utf8(bytes)?)
}


fn sent_params(request: &str) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("no request line")?;
    let query_text = target.strip_prefix("/?").ok_or("no query")?;
    query_text
        .split('&')
        .map(|pair| {
            let (name, value) = pair.split_once('=').ok_or("no equals")?;
            Ok((percent_decode(name)?, percent_decode(value)?))
        })
        .collect()
}


struct Endless {
    served: usize,
}


impl Read for Endless {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        buffer.fill(b'a');
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


fn fetch(port: u16, remaining: Duration) -> Result<FetchResult, Box<dyn Error>> {
    let config = settings(port);
    let agent = agent_for(&config)?;
    Ok(fetch_points(&agent, &config, PASSWORD, &query()?, remaining))
}


fn listener() -> Result<(TcpListener, u16), Box<dyn Error>> {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    Ok((bound, port))
}


#[test]
fn escape_param_table() -> TestResult {
    let cases = [
        ("plain", "plain"),
        ("a\\b", "a\\\\b"),
        ("a\tb", "a\\tb"),
        ("a\nb", "a\\nb"),
        ("a\rb", "a\\rb"),
        ("a\0b", "a\\0b"),
        ("it's", "it's"),
        ("{x}", "{x}"),
        ("", ""),
    ];
    cases.iter().for_each(|(raw, escaped)| assert_eq!(escape_param(raw), *escaped));
    Ok(())
}


#[test]
fn the_request_carries_every_param_escaped_and_the_format_suffix() -> TestResult {
    let (bound, port) = listener()?;
    let server = reply(bound, OK, "", format!("1\t{SINGLE}\n").into_bytes());
    let points = fetch(port, LONG)??;
    let request = server.join().map_err(|_| "server panicked")??;
    assert_eq!(points, vec![(1, SINGLE)]);
    let wanted: Vec<(String, String)> = query()?
        .params
        .iter()
        .map(|(name, value)| (format!("param_{name}"), escape_param(value)))
        .collect();
    assert_eq!(sent_params(&request)?, wanted);
    assert!(wanted.iter().any(|(name, value)| name == "param_tenant" && value == "acme"));
    assert!(wanted.iter().any(|(_, value)| value.contains("\\nx' OR 1=1 --")));
    assert!(wanted.iter().any(|(_, value)| value.contains("\\\\tmp\\tdir\\r\\0}")));
    assert!(!request.lines().next().unwrap_or("").contains("%0A"));
    let lowered = request.to_lowercase();
    assert!(lowered.contains("x-clickhouse-user: ostyr"));
    assert!(lowered.contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase())));
    assert!(request.trim_end().ends_with("FORMAT TabSeparated"), "{request}");
    assert!(request.contains("{tenant:String}"));
    Ok(())
}


#[test]
fn three_rows_are_parsed() -> TestResult {
    let (bound, port) = listener()?;
    let server = reply(bound, OK, "", b"1\t1.5\n2\t-2\n3\t1e3\n".to_vec());
    let points = fetch(port, LONG)??;
    server.join().map_err(|_| "server panicked")??;
    assert_eq!(points, vec![(1, FIRST), (TS_SECOND, SECOND), (TS_THIRD, THOUSAND)]);
    Ok(())
}


#[test]
fn an_empty_reply_is_an_empty_series() -> TestResult {
    let (bound, port) = listener()?;
    let server = reply(bound, OK, "", Vec::new());
    let points = fetch(port, LONG)??;
    server.join().map_err(|_| "server panicked")??;
    assert!(points.is_empty());
    Ok(())
}


#[test]
fn one_row_past_the_cap_is_refused_not_cut() -> TestResult {
    let (bound, port) = listener()?;
    let server = reply(bound, OK, "", "1\t1\n".repeat(MAX_FETCH_POINTS + 1).into_bytes());
    let outcome = fetch(port, LONG)?;
    server.join().map_err(|_| "server panicked")??;
    assert!(matches!(outcome, Err(FetchError::TooManyPoints)));
    assert_eq!(parse_points(&"1\t1\n".repeat(MAX_FETCH_POINTS))?.len(), MAX_FETCH_POINTS);
    Ok(())
}


#[test]
fn a_body_past_the_byte_cap_is_refused_with_bounded_memory() -> TestResult {
    let mut source = Endless { served: 0 };
    let outcome = read_points(&mut source);
    assert!(matches!(outcome, Err(FetchError::TooLarge)));
    assert_eq!(source.served as u64, MAX_FETCH_BYTES + 1);
    Ok(())
}


#[test]
fn an_endless_server_stream_stops_at_the_cap() -> TestResult {
    let (bound, port) = listener()?;
    let server = endless(bound);
    let outcome = fetch(port, LONG)?;
    let chunks = server.join().map_err(|_| "server panicked")??;
    assert!(matches!(outcome, Err(FetchError::TooLarge)));
    assert!(chunks > 0);
    Ok(())
}


#[test]
fn a_reply_that_never_comes_hits_the_deadline() -> TestResult {
    let (bound, port) = listener()?;
    let (release, held) = channel();
    let server = stall(bound, held);
    let outcome = fetch(port, DEADLINE)?;
    release.send(())?;
    server.join().map_err(|_| "server panicked")??;
    assert!(matches!(outcome, Err(FetchError::Failed(InsertClass::Timeout))));
    Ok(())
}


#[test]
fn a_body_that_never_ends_hits_the_deadline() -> TestResult {
    let (bound, port) = listener()?;
    let (release, held) = channel();
    let server = half_reply(bound, held);
    let outcome = fetch(port, DEADLINE)?;
    release.send(())?;
    server.join().map_err(|_| "server panicked")??;
    assert!(matches!(outcome, Err(FetchError::Body(_))), "{outcome:?}");
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let (bound, port) = listener()?;
    bound.set_nonblocking(true)?;
    let outcome = fetch(port, Duration::ZERO)?;
    assert!(matches!(outcome, Err(FetchError::Failed(InsertClass::Timeout))));
    assert_eq!(bound.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    Ok(())
}


#[test]
fn a_dead_peer_is_unavailable() -> TestResult {
    let (bound, port) = listener()?;
    drop(bound);
    let outcome = fetch(port, LONG)?;
    assert!(matches!(outcome, Err(FetchError::Failed(InsertClass::Unavailable))));
    Ok(())
}


#[test]
fn malformed_lines_fail_the_whole_fetch_counted_by_kind() -> TestResult {
    let outcome = parse_points("1\t1\nx\t1\n-5\t1\n1\tabc\n1\tnan\n1\tinf\n1\t-inf\n1\t2\t3\n\n7\n");
    let faults = match outcome {
        Err(FetchError::Malformed(faults)) => Some(faults),
        _ => None,
    }
    .ok_or("expected a malformed reply")?;
    assert_eq!(
        faults,
        LineFaults {
            columns: THREE,
            timestamp: TWO,
            value: 1,
            non_finite: THREE
        }
    );
    let text = FetchError::Malformed(faults).to_string();
    assert!(text.contains(&format!("{THREE} wrong column count")) && text.contains(&format!("{TWO} bad timestamp")));
    assert!(text.contains("1 bad value"));
    assert_eq!(parse_line("1\t2.5"), Ok((1, SINGLE)));
    assert_eq!(parse_line("1\tnan"), Err(LineFault::NonFinite));
    Ok(())
}


#[test]
fn a_server_error_is_classified_and_its_text_never_surfaces() -> TestResult {
    let (bound, port) = listener()?;
    let server = reply(bound, "500 Internal Server Error", "", b"SECRET-SERVER-TEXT".to_vec());
    let outcome = fetch(port, LONG)?;
    server.join().map_err(|_| "server panicked")??;
    let error = outcome.err().ok_or("expected a failure")?;
    assert!(matches!(error, FetchError::Failed(InsertClass::Unavailable)));
    assert!(!format!("{error} {error:?}").contains("SECRET-SERVER-TEXT"));
    Ok(())
}


#[test]
fn status_and_exception_code_pick_the_class() -> TestResult {
    let cases = [
        ("401 Unauthorized", "", InsertClass::Unauthorized),
        ("400 Bad Request", PARSE_CODE, InsertClass::ParseError),
        ("404 Not Found", "", InsertClass::Rejected),
        ("504 Gateway Timeout", "", InsertClass::Timeout),
    ];
    cases.iter().try_for_each(|(status, extra, class)| -> TestResult {
        let (bound, port) = listener()?;
        let server = reply(bound, status, extra, b"SECRET-SERVER-TEXT".to_vec());
        let outcome = fetch(port, LONG)?;
        server.join().map_err(|_| "server panicked")??;
        assert!(matches!(outcome, Err(FetchError::Failed(found)) if found == *class), "{status}");
        Ok(())
    })
}


#[test]
fn a_failing_body_reader_is_a_body_error() -> TestResult {
    assert!(matches!(read_points(Broken), Err(FetchError::Body(_))));
    Ok(())
}


#[test]
fn invalid_utf8_is_malformed_not_a_panic() -> TestResult {
    assert!(matches!(read_points(&BAD_BYTES[..]), Err(FetchError::Malformed(_))));
    Ok(())
}


#[test]
fn class_texts_are_fixed() -> TestResult {
    let classes = [
        InsertClass::ParseError,
        InsertClass::Unavailable,
        InsertClass::Timeout,
        InsertClass::Unauthorized,
        InsertClass::Rejected,
    ];
    let texts: Vec<&str> = classes.iter().map(|class| class_text(*class)).collect();
    assert_eq!(texts.len(), CLASS_COUNT);
    assert!(texts.iter().all(|text| !text.is_empty()));
    Ok(())
}


#[test]
fn error_texts_are_fixed() -> TestResult {
    assert!(FetchError::TooLarge.to_string().contains(&MAX_FETCH_BYTES.to_string()));
    assert!(FetchError::TooManyPoints.to_string().contains(&MAX_FETCH_POINTS.to_string()));
    assert!(FetchError::User.to_string().contains(&MAX_USER_BYTES.to_string()));
    assert!(FetchError::Timeout.to_string().contains(&MAX_TIMEOUT_MS.to_string()));
    assert_eq!(default_timeout_ms(), DEFAULT_TIMEOUT_MS);
    Ok(())
}


#[test]
fn settings_are_bounded() -> TestResult {
    let good = settings(1);
    validate_fetch_settings(&good)?;
    let bad_url = |url: &str| FetchSettings {
        url: url.to_string(),
        ..settings(1)
    };
    assert!(matches!(validate_fetch_settings(&bad_url("http://example.com")), Err(FetchError::Url(_))));
    assert!(matches!(
        validate_fetch_settings(&bad_url("https://u@example.com")),
        Err(FetchError::Url(_))
    ));
    assert!(validate_fetch_settings(&bad_url("https://example.com")).is_ok());
    let bad_user = |user: String| FetchSettings { user, ..settings(1) };
    assert!(matches!(validate_fetch_settings(&bad_user(String::new())), Err(FetchError::User)));
    assert!(matches!(validate_fetch_settings(&bad_user("a b".to_string())), Err(FetchError::User)));
    assert!(matches!(
        validate_fetch_settings(&bad_user("a".repeat(MAX_USER_BYTES + 1))),
        Err(FetchError::User)
    ));
    let bad_timeout = |timeout_ms: u64| FetchSettings { timeout_ms, ..settings(1) };
    assert!(matches!(validate_fetch_settings(&bad_timeout(0)), Err(FetchError::Timeout)));
    assert!(matches!(
        validate_fetch_settings(&bad_timeout(MAX_TIMEOUT_MS + 1)),
        Err(FetchError::Timeout)
    ));
    assert!(validate_fetch_settings(&bad_timeout(MAX_TIMEOUT_MS)).is_ok());
    Ok(())
}


#[test]
fn settings_load_strictly() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    fs::write(&path, "url: http://127.0.0.1:1\nuser: ostyr\npassword_file: /p\n")?;
    let loaded = load_fetch_settings(&path)?;
    assert_eq!(loaded.timeout_ms, DEFAULT_TIMEOUT_MS);
    assert_eq!(loaded.ca_file, None);
    fs::write(&path, "url: http://127.0.0.1:1\nuser: ostyr\npassword_file: /p\nextra: 1\n")?;
    assert!(matches!(load_fetch_settings(&path), Err(FetchError::Config(_))));
    fs::write(&path, "url: http://example.com\nuser: ostyr\npassword_file: /p\n")?;
    assert!(matches!(load_fetch_settings(&path), Err(FetchError::Url(_))));
    Ok(())
}


#[test]
fn the_agent_reads_the_ca_through_checked_handles() -> TestResult {
    let dir = tempdir()?;
    let ca = dir.path().join("ca.pem");
    let with_ca = |path: &std::path::Path| FetchSettings {
        url: "https://example.com".to_string(),
        ca_file: Some(path.to_path_buf()),
        ..settings(1)
    };
    assert!(matches!(agent_for(&with_ca(&ca)), Err(FetchError::CaFile(_))));
    fs::write(&ca, vec![b'a'; MAX_CA_BYTES as usize + 1])?;
    assert!(matches!(agent_for(&with_ca(&ca)), Err(FetchError::CaFile(_))));
    fs::write(&ca, "not a certificate")?;
    assert!(matches!(agent_for(&with_ca(&ca)), Err(FetchError::Agent(_))));
    assert!(agent_for(&FetchSettings {
        url: "https://example.com".to_string(),
        ..settings(1)
    })
    .is_ok());
    assert!(matches!(
        agent_for(&FetchSettings {
            url: "http://example.com".to_string(),
            ..settings(1)
        }),
        Err(FetchError::Url(_))
    ));
    Ok(())
}


#[test]
fn the_password_is_read_through_the_checked_reader() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("password");
    let with_file = FetchSettings {
        password_file: file.clone(),
        ..settings(1)
    };
    assert!(matches!(read_key(&with_file), Err(FetchError::Password(_))));
    fs::write(&file, format!("{PASSWORD}\n"))?;
    assert_eq!(read_key(&with_file)?.as_str(), PASSWORD);
    fs::write(&file, BAD_BYTES)?;
    assert!(matches!(read_key(&with_file), Err(FetchError::PasswordEncoding(_))));
    Ok(())
}
