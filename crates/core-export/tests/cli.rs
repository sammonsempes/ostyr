#[path = "common/http_sink.rs"]
mod http_sink;
#[path = "common/pki.rs"]
mod pki;
#[path = "common/tls_sink.rs"]
mod tls_sink;
#[path = "common/types.rs"]
mod types;


use core_config::secret::SecretRef;
use core_export::cli::{run, run_syslog, sample_event, sample_events, syslog_command, webhook_command};
use core_export::config::parse_export;
use core_export::error::ExportError;
use core_export::types::BoxError;
use core_export::webhook::RetryPolicy;
use std::fs::{self, File};
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const STATUS_OK: u16 = 200;


const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);


const DATAGRAM_BUFFER: usize = 65_536;


const TWO_ATTEMPTS: u32 = 2;


const SAMPLE_COUNT: u64 = 3;


const FIRST_SEQUENCE: u64 = 10;


const NAMED_SEQUENCE: u64 = 5;


const TWO_EVENTS: u64 = 2;


const BUFFER_TOO_SMALL: u64 = 10;


fn now() -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(FIXED_UNIX)
}


fn no_secret(_reference: &SecretRef) -> Result<String, BoxError> {
    Err("no backend".into())
}


fn token_secret(_reference: &SecretRef) -> Result<String, BoxError> {
    Ok("tok".to_string())
}


fn webhook_yaml(url: &str, buffer: &Path, extra: &str) -> String {
    format!("webhook:\n  url: {url}\n  buffer_dir: {}\n{extra}", buffer.display())
}


fn fast_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: TWO_ATTEMPTS,
        ..RetryPolicy::default()
    }
}


#[test]
fn sample_events_carry_consecutive_sequence_numbers() -> TestResult {
    let events = sample_events(SAMPLE_COUNT, FIRST_SEQUENCE, now()?);
    let expected = (FIRST_SEQUENCE..FIRST_SEQUENCE + SAMPLE_COUNT).map(Some).collect::<Vec<_>>();
    assert_eq!(events.iter().map(|event| event.event.sequence).collect::<Vec<_>>(), expected);
    assert_eq!(
        sample_event(NAMED_SEQUENCE, now()?).message,
        Some(format!("sample event {NAMED_SEQUENCE}"))
    );
    assert!(sample_events(0, 0, now()?).is_empty());
    Ok(())
}


#[test]
fn run_rejects_bad_arguments() -> TestResult {
    let mut out = Vec::new();
    assert!(matches!(run(&[], &mut out, &no_secret), Err(ExportError::Usage)));
    assert!(matches!(
        run(&["webhook", "cfg", "x", "0"], &mut out, &no_secret),
        Err(ExportError::Usage)
    ));
    assert!(matches!(
        run(&["webhook", "cfg", "1", "x"], &mut out, &no_secret),
        Err(ExportError::Usage)
    ));
    assert!(matches!(run(&["other", "cfg", "1", "0"], &mut out, &no_secret), Err(ExportError::Usage)));
    Ok(())
}


#[test]
fn run_sends_to_the_webhook_with_the_resolved_token() -> TestResult {
    let dir = tempdir()?;
    let http_sink::HttpSink { port, bodies } = http_sink::spawn_http_sink(None, vec![STATUS_OK])?;
    let config = dir.path().join("export.yaml");
    fs::write(
        &config,
        webhook_yaml(
            &format!("http://127.0.0.1:{port}/hook"),
            &dir.path().join("buf"),
            "  token: vault://kv/t\n",
        ),
    )?;
    let mut out = Vec::new();
    run(&["webhook", &config.display().to_string(), "3", "100"], &mut out, &token_secret)?;
    assert_eq!(String::from_utf8(out)?, "sent=1 buffered=0 drained=0 dropped=0\n");
    let received = bodies.join().map_err(|_panic| "sink thread panicked")??;
    assert_eq!(received.len(), 1);
    assert_eq!(received.first().map(|(auth, _body)| auth.as_str()), Some("bearer tok"));
    assert!(received.first().is_some_and(|(_auth, body)| body.contains("\"sequence\":102")));
    Ok(())
}


#[test]
fn a_secret_that_cannot_be_resolved_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let config = parse_export(
        &webhook_yaml("http://127.0.0.1:1/h", &dir.path().join("buf"), "  token: vault://kv/t\n"),
        "export.yaml",
    )?;
    let result = webhook_command(&mut Vec::new(), &config, &[], &no_secret, &fast_policy(), &mut |_delay| {}, now()?);
    assert!(matches!(result, Err(ExportError::Secret(_))));
    Ok(())
}


#[test]
fn a_saturated_buffer_prints_the_alert() -> TestResult {
    let dir = tempdir()?;
    let closed = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let config = parse_export(
        &webhook_yaml(
            &format!("http://127.0.0.1:{closed}/h"),
            &dir.path().join("buf"),
            &format!("  buffer_max_bytes: {BUFFER_TOO_SMALL}\n"),
        ),
        "export.yaml",
    )?;
    let mut out = Vec::new();
    webhook_command(
        &mut out,
        &config,
        &sample_events(TWO_EVENTS, 0, now()?),
        &no_secret,
        &fast_policy(),
        &mut |_delay| {},
        now()?,
    )?;
    let text = String::from_utf8(out)?;
    assert!(text.starts_with("sent=0 buffered=0 drained=0 dropped=2\nalert {"));
    assert!(text.contains("export-buffer-saturated"));
    Ok(())
}


#[test]
fn a_missing_ca_file_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let config = parse_export(
        &webhook_yaml(
            "https://127.0.0.1:1/h",
            &dir.path().join("buf"),
            &format!("  ca_file: {}/absent.pem\n", dir.path().display()),
        ),
        "export.yaml",
    )?;
    let result = webhook_command(&mut Vec::new(), &config, &[], &no_secret, &fast_policy(), &mut |_delay| {}, now()?);
    assert!(matches!(result, Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn a_command_needs_its_section() -> TestResult {
    let config = parse_export("syslog:\n  address: a:1\n  hostname: h\n", "export.yaml")?;
    let none = parse_export("{}", "export.yaml")?;
    assert!(matches!(
        webhook_command(&mut Vec::new(), &config, &[], &no_secret, &fast_policy(), &mut |_delay| {}, now()?),
        Err(ExportError::MissingSection("webhook"))
    ));
    assert!(matches!(
        syslog_command(&mut Vec::new(), &none, &[]),
        Err(ExportError::MissingSection("syslog"))
    ));
    Ok(())
}


#[test]
fn syslog_over_udp_sends_one_datagram_per_event() -> TestResult {
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    receiver.set_read_timeout(Some(RECEIVE_TIMEOUT))?;
    let config = parse_export(
        &format!("syslog:\n  address: {}\n  transport: udp\n  hostname: srv1\n", receiver.local_addr()?),
        "export.yaml",
    )?;
    let mut out = Vec::new();
    syslog_command(&mut out, &config, &sample_events(TWO_EVENTS, 0, now()?))?;
    assert_eq!(String::from_utf8(out)?, "sent=2\n");
    let mut buffer = vec![u8::MIN; DATAGRAM_BUFFER];
    let size = receiver.recv(&mut buffer)?;
    let text = String::from_utf8(buffer.get(..size).ok_or("short read")?.to_vec())?;
    assert!(text.starts_with("<134>1 2023-11-14T22:13:20Z srv1 ostyr - ecs - {"));
    Ok(())
}


#[test]
fn syslog_over_tls_delivers_framed_messages() -> TestResult {
    let dir = tempdir()?;
    let authority = pki::test_pki()?;
    let ca_file = dir.path().join("ca.pem");
    fs::write(&ca_file, &authority.ca_pem)?;
    let tls_sink::TlsSink { address, received } = tls_sink::spawn_tls_sink(authority.server_config.clone())?;
    let config = parse_export(
        &format!("syslog:\n  address: {address}\n  hostname: srv1\n  ca_file: {}\n", ca_file.display()),
        "export.yaml",
    )?;
    let syslog = config.syslog.ok_or("syslog expected")?;
    run_syslog(&syslog, &sample_events(TWO_EVENTS, 0, now()?))?;
    let text = String::from_utf8(received.join().map_err(|_panic| "sink thread panicked")??)?;
    assert_eq!(text.matches("<134>1 ").count(), TWO_EVENTS as usize);
    assert!(text.starts_with(|digit: char| digit.is_ascii_digit()));
    Ok(())
}


#[test]
fn syslog_reports_a_missing_ca_file() -> TestResult {
    let config = parse_export(
        "syslog:\n  address: localhost:1\n  hostname: h\n  ca_file: /nonexistent/ca.pem\n",
        "export.yaml",
    )?;
    let syslog = config.syslog.ok_or("syslog expected")?;
    assert!(matches!(run_syslog(&syslog, &[]), Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn an_unwritable_output_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("out");
    File::create(&path)?;
    let mut read_only = File::open(&path)?;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let config = parse_export(
        &format!("syslog:\n  address: {}\n  transport: udp\n  hostname: srv1\n", receiver.local_addr()?),
        "export.yaml",
    )?;
    assert!(matches!(syslog_command(&mut read_only, &config, &[]), Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn run_dispatches_syslog() -> TestResult {
    let dir = tempdir()?;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let config = dir.path().join("export.yaml");
    fs::write(
        &config,
        format!("syslog:\n  address: {}\n  transport: udp\n  hostname: srv1\n", receiver.local_addr()?),
    )?;
    let mut out = Vec::new();
    run(&["syslog", &config.display().to_string(), "1", "0"], &mut out, &no_secret)?;
    assert_eq!(String::from_utf8(out)?, "sent=1\n");
    Ok(())
}
