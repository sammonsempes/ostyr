mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, AnyValue, KeyValue};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;
use stub::serve;
use tempfile::{tempdir, TempDir};
use traces_ingest::insert::RefusedSpan;
use traces_ingest::insert_cli::{insert_error_text, run_insert_cli, InsertCliError, INSERT_USAGE};
use traces_ingest::model::{DropReason, Refusal};
use traces_ingest::run::{run_insert, write_report, RunError, RunReport};
use traces_ingest::sampling::Sampling;


const NOW: u64 = 1_700_000_000_000_000_000;


const NANOS_PER_SECOND: u64 = 1_000_000_000;


const YEAR_SECONDS: u64 = 31_536_000;


const PASSWORD: &str = "TRACEPW-7c1d9a40";


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


const LONG_TIMEOUT_MS: u64 = 300_000;


const SPAN_ID_BYTES: usize = 8;


const TRACE_ID_BYTES: usize = 16;


const SERVER_KIND: i32 = 2;


const SECOND: u8 = 2;


const REPORT_WRITES: usize = 64;


const SPANS: usize = 2;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


struct Rig {
    dir: TempDir,
    listener: TcpListener,
    settings: PathBuf,
}


fn rig() -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    fs::write(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let settings = dir.path().join("settings.yaml");
    fs::write(
        &settings,
        format!(
            "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: trace_spans\ntimeout_ms: {LONG_TIMEOUT_MS}\n",
            dir.path().join("password").display()
        ),
    )?;
    Ok(Rig { dir, listener, settings })
}


fn text(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(AnyKind::StringValue(value.to_string())),
        }),
        ..Default::default()
    }
}


fn span(seed: u8, start: u64, trace_len: usize) -> Span {
    Span {
        trace_id: vec![seed; trace_len],
        span_id: vec![seed; SPAN_ID_BYTES],
        name: "op".to_string(),
        kind: SERVER_KIND,
        start_time_unix_nano: start,
        end_time_unix_nano: start + 1,
        attributes: vec![text("tenant", "evil")],
        ..Default::default()
    }
}


fn request(spans: Vec<Span>) -> Vec<u8> {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans { spans, ..Default::default() }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}


fn good() -> Vec<u8> {
    request(vec![span(1, NOW, TRACE_ID_BYTES), span(SECOND, NOW, TRACE_ID_BYTES)])
}


fn go(rig: &Rig, bytes: &[u8], tenant: &str) -> Result<RunReport, RunError> {
    run_insert(&rig.settings, bytes, tenant, &Sampling::default(), NOW, &|| Duration::ZERO)
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


fn joined<Output>(handle: std::thread::JoinHandle<io::Result<Output>>) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


struct FailAfter {
    left: usize,
}


struct Broken;


impl Write for Broken {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.left == 0 {
            Err(io::Error::other("closed"))
        } else {
            self.left -= 1;
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn args(rig: &Rig, request_file: &str, sampling_file: &str, tenant: &str) -> Vec<String> {
    vec![
        rig.settings.display().to_string(),
        rig.dir.path().join(request_file).display().to_string(),
        rig.dir.path().join(sampling_file).display().to_string(),
        tenant.to_string(),
    ]
}


fn files(rig: &Rig, sampling: &[u8]) -> TestResult {
    fs::write(rig.dir.path().join("request.pb"), good())?;
    fs::write(rig.dir.path().join("sampling.yaml"), sampling)?;
    Ok(())
}


#[test]
fn one_batch_goes_with_the_key_in_a_header_only_and_the_tenant_from_the_argument() -> TestResult {
    let rig = rig()?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    let report = go(&rig, &good(), "acme")?;
    assert_eq!(
        (report.rows, report.batches_planned, report.batches_sent, report.failed_batch),
        (SPANS, 1, 1, None)
    );
    let seen = joined(server)?;
    let one = seen.first().ok_or("no request")?;
    let head = one.lines().next().ok_or("no head")?;
    assert!(head.starts_with("POST /?query=INSERT"), "{head}");
    assert!(head.contains("%60ostyr%60.%60trace_spans%60"), "{head}");
    assert!(head.contains("input("), "{head}");
    assert!(!head.contains(PASSWORD));
    assert!(one.to_lowercase().contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase())));
    let body = one.split("\r\n\r\n").nth(1).ok_or("no body")?;
    assert_eq!(body.lines().count(), SPANS);
    assert!(body
        .lines()
        .all(|line| line.contains("\"tenant\":\"acme\"") && line.contains("\"attributes\":{\"tenant\":\"evil\"}")));
    Ok(())
}


#[test]
fn a_server_error_is_a_failed_first_batch() -> TestResult {
    let rig = rig()?;
    let server = serve(rig.listener.try_clone()?, vec![SERVER_ERROR]);
    let report = go(&rig, &good(), "acme")?;
    assert_eq!((report.batches_planned, report.batches_sent, report.failed_batch), (1, 0, Some(0)));
    joined(server)?;
    Ok(())
}


#[test]
fn a_refused_tenant_touches_nothing() -> TestResult {
    let rig = rig()?;
    let report = go(&rig, &good(), "-x")?;
    assert!(matches!(report.refusal, Some(Refusal::InvalidTenant(_))));
    assert_eq!((report.rows, report.batches_planned, report.batches_sent), (0, 0, 0));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn rows_out_of_the_time_window_send_nothing() -> TestResult {
    let rig = rig()?;
    let old = NOW - YEAR_SECONDS * NANOS_PER_SECOND;
    let bytes = request(vec![span(1, old, TRACE_ID_BYTES)]);
    let report = go(&rig, &bytes, "acme")?;
    assert_eq!(report.refused.get(&RefusedSpan::TimestampOutOfRange), Some(&1));
    assert_eq!(
        (report.rows, report.batches_planned, report.batches_sent, report.failed_batch),
        (1, 0, 0, None)
    );
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_missing_password_file_is_a_sender_error_before_any_connection() -> TestResult {
    let rig = rig()?;
    fs::remove_file(rig.dir.path().join("password"))?;
    assert!(matches!(go(&rig, &good(), "acme"), Err(RunError::Send(_))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_bad_settings_file_is_a_settings_error() -> TestResult {
    let rig = rig()?;
    fs::write(&rig.settings, "url: nope\n")?;
    assert!(matches!(go(&rig, &good(), "acme"), Err(RunError::Settings(_))));
    Ok(())
}


#[test]
fn the_report_lists_counts_only() -> TestResult {
    let rig = rig()?;
    let bytes = request(vec![span(1, NOW, TRACE_ID_BYTES), span(SECOND, NOW, 1)]);
    let server = serve(rig.listener.try_clone()?, vec![SERVER_ERROR]);
    let report = go(&rig, &bytes, "acme")?;
    joined(server)?;
    let mut out = Vec::new();
    write_report(&report, &mut out)?;
    let printed = String::from_utf8(out)?;
    assert!(printed.contains("tenant acme\nrows 1\nsampled_out 0\n"), "{printed}");
    assert!(printed.contains("dropped bad_id 1\n"), "{printed}");
    assert!(printed.contains("batches planned 1\nbatches sent 0\nfailed batch 0\n"), "{printed}");
    let refused = go(&rig, &bytes, "-x")?;
    let mut again = Vec::new();
    write_report(&refused, &mut again)?;
    assert!(String::from_utf8(again)?.contains("request refused InvalidTenant"));
    let old = request(vec![span(1, NOW - YEAR_SECONDS * NANOS_PER_SECOND, TRACE_ID_BYTES)]);
    let mut third = Vec::new();
    write_report(&go(&rig, &old, "acme")?, &mut third)?;
    assert!(String::from_utf8(third)?.contains("refused timestamp_out_of_range 1\n"));
    assert!(write_report(&report, &mut Broken).is_err());
    Ok(())
}


#[test]
fn the_cli_inserts_and_reports() -> TestResult {
    let rig = rig()?;
    files(&rig, b"default_ratio: 1.0\n")?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    let mut out = Vec::new();
    run_insert_cli(&args(&rig, "request.pb", "sampling.yaml", "acme"), NOW, &|| Duration::ZERO, &mut out)?;
    joined(server)?;
    assert!(String::from_utf8(out)?.contains("batches sent 1"));
    Ok(())
}


#[test]
fn the_cli_fails_after_the_report_when_a_batch_fails() -> TestResult {
    let rig = rig()?;
    files(&rig, b"default_ratio: 1.0\n")?;
    let server = serve(rig.listener.try_clone()?, vec![SERVER_ERROR]);
    let mut out = Vec::new();
    let error = run_insert_cli(&args(&rig, "request.pb", "sampling.yaml", "acme"), NOW, &|| Duration::ZERO, &mut out)
        .err()
        .ok_or("no error")?;
    joined(server)?;
    assert!(matches!(error, InsertCliError::BatchFailed(0)));
    assert!(String::from_utf8(out)?.contains("failed batch 0"));
    assert_eq!(insert_error_text(&error), "batch 0 failed, see the report");
    Ok(())
}


#[test]
fn the_cli_refuses_bad_input_with_fixed_texts() -> TestResult {
    let rig = rig()?;
    files(&rig, b"default_ratio: 1.0\n")?;
    let run = |arguments: &[String]| run_insert_cli(arguments, NOW, &|| Duration::ZERO, &mut Vec::new()).err();
    let usage = run(&[]).ok_or("no usage error")?;
    assert_eq!(insert_error_text(&usage), INSERT_USAGE);
    let missing_request = run(&args(&rig, "absent.pb", "sampling.yaml", "acme")).ok_or("no error")?;
    assert!(matches!(missing_request, InsertCliError::Request(_)));
    assert_eq!(insert_error_text(&missing_request), "the request file could not be read");
    let missing_sampling = run(&args(&rig, "request.pb", "absent.yaml", "acme")).ok_or("no error")?;
    assert!(matches!(missing_sampling, InsertCliError::SamplingFile(_)));
    assert_eq!(insert_error_text(&missing_sampling), "the sampling file is refused");
    fs::write(rig.dir.path().join("binary.yaml"), NOT_UTF8)?;
    let binary = run(&args(&rig, "request.pb", "binary.yaml", "acme")).ok_or("no error")?;
    assert!(matches!(binary, InsertCliError::SamplingText(_)));
    fs::write(rig.dir.path().join("wide.yaml"), "default_ratio: 2.0\n")?;
    let wide = run(&args(&rig, "request.pb", "wide.yaml", "acme")).ok_or("no error")?;
    assert!(matches!(wide, InsertCliError::Sampling(_)));
    assert_eq!(insert_error_text(&wide), "the sampling file is refused");
    fs::write(&rig.settings, "url: nope\n")?;
    let settings = run(&args(&rig, "request.pb", "sampling.yaml", "acme")).ok_or("no error")?;
    assert!(matches!(settings, InsertCliError::Run(_)));
    assert_eq!(insert_error_text(&settings), "the settings or the sender are refused");
    Ok(())
}


#[test]
fn the_cli_reports_a_broken_output() -> TestResult {
    let rig = rig()?;
    files(&rig, b"default_ratio: 1.0\n")?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    let error = run_insert_cli(&args(&rig, "request.pb", "sampling.yaml", "acme"), NOW, &|| Duration::ZERO, &mut Broken)
        .err()
        .ok_or("no error")?;
    joined(server)?;
    assert!(matches!(error, InsertCliError::Output(_)));
    assert_eq!(insert_error_text(&error), "the report could not be written");
    Ok(())
}


#[test]
fn every_write_of_the_report_can_fail() -> TestResult {
    let report = RunReport {
        tenant: "acme".to_string(),
        rows: 1,
        dropped: [(DropReason::BadId, 1)].into_iter().collect(),
        sampled_out: 0,
        refusal: Some(Refusal::TooLarge { bytes: 1 }),
        refused: [(RefusedSpan::RowTooLarge, 1)].into_iter().collect(),
        batches_planned: 1,
        batches_sent: 0,
        failed_batch: Some(0),
    };
    let failures = (0..REPORT_WRITES)
        .filter(|left| write_report(&report, &mut FailAfter { left: *left }).is_err())
        .count();
    assert!(failures > 1 && failures < REPORT_WRITES);
    assert!(write_report(&report, &mut FailAfter { left: REPORT_WRITES }).is_ok());
    Ok(())
}
