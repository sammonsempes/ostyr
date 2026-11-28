#![cfg(unix)]

mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use metrics_ingest::send::SendError;
use metrics_ingest::settings::{LoadError, SettingsError};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, AnyValue, KeyValue};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use siem_ingest::error::InsertClass;
use std::cell::Cell;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;
use stub::serve;
use tempfile::{tempdir, TempDir};
use traces_ingest::model::Limits;
use traces_ingest::receive::{
    error_text, receive_export, Reply, STATUS_BAD_REQUEST, STATUS_INTERNAL, STATUS_OK, STATUS_TOO_LARGE, STATUS_UNAUTHORIZED, STATUS_UNAVAILABLE,
};
use traces_ingest::run::{class_of, run_insert_with, RunError};
use traces_ingest::sampling::Sampling;
use traces_ingest::settings::{load_traces_settings, TracesSettings};
use ExportTraceServiceResponse as Response;


const NOW: u64 = 1_700_000_000_000_000_000;


const LONG_TIMEOUT_MS: u64 = 300_000;


const SPAN_ID_BYTES: usize = 8;


const TRACE_ID_BYTES: usize = 16;


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


const GATEWAY_TIMEOUT: &str = "504 Gateway Timeout";


const NOT_FOUND: &str = "404 Not Found";


const FORBIDDEN: &str = "403 Forbidden";


const SPAN_COUNT: u8 = 6;


const ONE_PER_BATCH: usize = 1;


const SECRET_MODE: u32 = 0o600;


const SHORT_TIMEOUT_MS: u64 = 20_000;


const YEAR_NANOS: u64 = 31_536_000_000_000_000;


const WIDE_BATCH: usize = 100;


const PAIR: u8 = 2;


const TRIPLE: u8 = 3;


const NO_SAMPLING: f64 = 0.0;


const LOWERED_REQUEST_BYTES: usize = 8;


const NOT_PROTOBUF: [u8; 3] = [u8::MAX; 3];


const MARKER: &str = "TRACEPW-marker-5521";


struct Rig {
    _dir: TempDir,
    listener: TcpListener,
    settings: TracesSettings,
    password: PathBuf,
}


fn rig(batch_rows: usize) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let password = dir.path().join("password");
    fs::write(&password, format!("{MARKER}\n"))?;
    fs::set_permissions(&password, std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))?;
    let file = dir.path().join("settings.yaml");
    fs::write(
        &file,
        format!(
            "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: trace_spans\ntimeout_ms: {LONG_TIMEOUT_MS}\nlimits:\n  \
             max_batch_rows: {batch_rows}\n",
            password.display()
        ),
    )?;
    let settings = load_traces_settings(&file)?;
    Ok(Rig {
        _dir: dir,
        listener,
        settings,
        password,
    })
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


fn span(seed: u8, trace_len: usize) -> Span {
    Span {
        trace_id: vec![seed; trace_len],
        span_id: vec![seed; SPAN_ID_BYTES],
        name: "op".to_string(),
        start_time_unix_nano: NOW,
        end_time_unix_nano: NOW + 1,
        attributes: vec![text("tenant", "evil")],
        ..Default::default()
    }
}


fn request(spans: Vec<Span>) -> Vec<u8> {
    ExportTraceServiceResponse::default();
    opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans { spans, ..Default::default() }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}


fn spans(count: u8) -> Vec<u8> {
    request((1..=count).map(|seed| span(seed, TRACE_ID_BYTES)).collect())
}


fn go(rig: &Rig, bytes: &[u8], admitted: &dyn Fn() -> bool) -> Reply {
    receive_export(&rig.settings, &Sampling::default(), bytes, "acme", admitted, NOW, &|| Duration::ZERO)
}


fn partial(reply: &Reply) -> Result<(i64, String), Box<dyn std::error::Error>> {
    let decoded = Response::decode(reply.body.as_slice())?;
    let found = decoded.partial_success.ok_or("no partial success")?;
    Ok((found.rejected_spans, found.error_message))
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


fn joined<Output>(handle: std::thread::JoinHandle<io::Result<Output>>) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


#[test]
fn a_stored_export_is_200_with_no_partial_success() -> TestResult {
    let rig = rig(WIDE_BATCH)?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    let reply = go(&rig, &spans(PAIR), &|| true);
    joined(server)?;
    assert_eq!((reply.status, reply.retry_after), (STATUS_OK, false));
    assert_eq!(reply.content_type, "application/x-protobuf");
    assert_eq!(Response::decode(reply.body.as_slice())?.partial_success, None);
    Ok(())
}


#[test]
fn dropped_spans_are_rejected_and_sampled_out_spans_are_not() -> TestResult {
    let rig = rig(WIDE_BATCH)?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    let mixed = request(vec![span(1, TRACE_ID_BYTES), span(PAIR, 1), span(TRIPLE, 1)]);
    let reply = go(&rig, &mixed, &|| true);
    joined(server)?;
    let (rejected, message) = partial(&reply)?;
    assert_eq!(rejected, i64::from(PAIR));
    assert!(message.contains("bad_id 2") && message.contains("not stored 0"), "{message}");
    let none = Sampling {
        default_ratio: NO_SAMPLING,
        ..Sampling::default()
    };
    let sampled = receive_export(&rig.settings, &none, &spans(PAIR), "acme", &|| true, NOW, &|| Duration::ZERO);
    assert_eq!(sampled.status, STATUS_OK);
    assert_eq!(Response::decode(sampled.body.as_slice())?.partial_success, None);
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_failure_after_a_stored_batch_is_200_with_the_unsent_rows_counted() -> TestResult {
    let rig = rig(ONE_PER_BATCH)?;
    let server = serve(rig.listener.try_clone()?, vec![OK, SERVER_ERROR]);
    let reply = go(&rig, &spans(SPAN_COUNT), &|| true);
    joined(server)?;
    assert_eq!(reply.status, STATUS_OK);
    let (rejected, message) = partial(&reply)?;
    assert_eq!(rejected, i64::from(SPAN_COUNT) - 1);
    assert!(message.contains("not stored 5"), "{message}");
    assert!(!message.contains(MARKER));
    Ok(())
}


#[test]
fn nothing_stored_is_503_with_retry_after_for_an_unavailable_store_and_500_for_a_refusal() -> TestResult {
    let rig = rig(ONE_PER_BATCH)?;
    let server = serve(rig.listener.try_clone()?, vec![SERVER_ERROR]);
    let down = go(&rig, &spans(PAIR), &|| true);
    joined(server)?;
    assert_eq!((down.status, down.retry_after), (STATUS_UNAVAILABLE, true));
    let timing_out = serve(rig.listener.try_clone()?, vec![GATEWAY_TIMEOUT]);
    let slow = go(&rig, &spans(PAIR), &|| true);
    joined(timing_out)?;
    assert_eq!((slow.status, slow.retry_after), (STATUS_UNAVAILABLE, true));
    let missing = serve(rig.listener.try_clone()?, vec![NOT_FOUND]);
    let rejected = go(&rig, &spans(PAIR), &|| true);
    joined(missing)?;
    assert_eq!(rejected.status, STATUS_INTERNAL);
    let forbidding = serve(rig.listener.try_clone()?, vec![FORBIDDEN]);
    let refused = go(&rig, &spans(PAIR), &|| true);
    joined(forbidding)?;
    assert_eq!((refused.status, refused.retry_after), (STATUS_INTERNAL, false));
    assert!(!String::from_utf8_lossy(&refused.body).contains(MARKER));
    Ok(())
}


#[test]
fn a_sender_removed_before_the_first_batch_is_401_and_nothing_is_sent() -> TestResult {
    let rig = rig(ONE_PER_BATCH)?;
    let quick = TracesSettings {
        timeout_ms: SHORT_TIMEOUT_MS,
        ..rig.settings.clone()
    };
    let reply = receive_export(&quick, &Sampling::default(), &spans(PAIR), "acme", &|| false, NOW, &|| Duration::ZERO);
    assert_eq!(reply.status, STATUS_UNAUTHORIZED);
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_sender_removed_between_batches_stops_the_sends_and_counts_the_rest() -> TestResult {
    let rig = rig(ONE_PER_BATCH)?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    let asked = Cell::new(u8::MIN);
    let admitted = || {
        asked.set(asked.get() + 1);
        asked.get() == 1
    };
    let quick = TracesSettings {
        timeout_ms: SHORT_TIMEOUT_MS,
        ..rig.settings.clone()
    };
    let report = run_insert_with(
        &quick,
        &spans(SPAN_COUNT),
        "acme",
        &Sampling::default(),
        NOW,
        &|| Duration::ZERO,
        &admitted,
    )?;
    joined(server)?;
    assert!(report.revoked);
    assert_eq!((report.batches_sent, report.unsent_rows), (1, usize::from(SPAN_COUNT) - 1));
    Ok(())
}


#[test]
fn refusals_are_400_and_a_request_over_the_snapshot_limit_is_413() -> TestResult {
    let rig = rig(WIDE_BATCH)?;
    let garbage = go(&rig, NOT_PROTOBUF.as_slice(), &|| true);
    assert_eq!(garbage.status, STATUS_BAD_REQUEST);
    let lowered = TracesSettings {
        limits: Limits {
            max_request_bytes: LOWERED_REQUEST_BYTES,
            ..Limits::default()
        },
        ..rig.settings.clone()
    };
    let big = receive_export(&lowered, &Sampling::default(), &spans(PAIR), "acme", &|| true, NOW, &|| Duration::ZERO);
    assert_eq!(big.status, STATUS_TOO_LARGE);
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_settings_or_sender_failure_is_a_fixed_500_that_names_no_secret() -> TestResult {
    let rig = rig(WIDE_BATCH)?;
    fs::remove_file(&rig.password)?;
    let reply = go(&rig, &spans(PAIR), &|| true);
    assert_eq!(reply.status, STATUS_INTERNAL);
    let body = String::from_utf8(reply.body)?;
    assert!(!body.contains(MARKER) && !body.contains("password"), "{body}");
    let zero = TracesSettings {
        limits: Limits {
            max_batch_rows: 0,
            ..Limits::default()
        },
        ..rig.settings.clone()
    };
    let encode = receive_export(&zero, &Sampling::default(), &spans(PAIR), "acme", &|| true, NOW, &|| Duration::ZERO);
    assert_eq!(encode.status, STATUS_INTERNAL);
    let bad_table = TracesSettings {
        table: "a b".to_string(),
        ..rig.settings.clone()
    };
    let statement = receive_export(&bad_table, &Sampling::default(), &spans(PAIR), "acme", &|| true, NOW, &|| Duration::ZERO);
    assert_eq!(statement.status, STATUS_INTERNAL);
    Ok(())
}


#[test]
fn a_span_older_than_the_retention_window_is_rejected_by_name() -> TestResult {
    let rig = rig(WIDE_BATCH)?;
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    let old = Span {
        start_time_unix_nano: NOW - YEAR_NANOS,
        end_time_unix_nano: NOW - YEAR_NANOS + 1,
        ..span(1, TRACE_ID_BYTES)
    };
    let mixed = request(vec![old, span(PAIR, TRACE_ID_BYTES)]);
    let reply = go(&rig, &mixed, &|| true);
    joined(server)?;
    let (rejected, message) = partial(&reply)?;
    assert_eq!(rejected, 1);
    assert!(message.contains("timestamp_out_of_range 1"), "{message}");
    Ok(())
}


#[test]
fn only_a_refused_batch_has_a_class() -> TestResult {
    assert_eq!(class_of(&SendError::Failed(InsertClass::Timeout)), Some(InsertClass::Timeout));
    assert_eq!(class_of(&SendError::Settings(SettingsError::User)), None);
    Ok(())
}


#[test]
fn the_log_text_is_fixed_for_every_run_error() -> TestResult {
    let rig = rig(WIDE_BATCH)?;
    fs::remove_file(&rig.password)?;
    let send = run_insert_with(
        &rig.settings,
        &spans(PAIR),
        "acme",
        &Sampling::default(),
        NOW,
        &|| Duration::ZERO,
        &|| true,
    )
    .err()
    .ok_or("no error")?;
    assert!(matches!(send, RunError::Send(_)));
    assert!(!error_text(&send).contains(MARKER));
    let settings = RunError::Settings(LoadError::Invalid(SettingsError::User));
    assert_eq!(error_text(&settings), "the settings are refused");
    let statement = RunError::Statement(SettingsError::Timeout);
    assert_eq!(error_text(&statement), "the settings are refused");
    let encode = RunError::Encode(metrics_ingest::insert::EncodeError::ZeroBatchRows);
    assert_eq!(error_text(&encode), "the batch limits are refused");
    Ok(())
}
