#[path = "common/http_sink.rs"]
mod http_sink;
#[path = "common/types.rs"]
mod types;


use core_export::buffer::list_batches;
use core_export::cli::{run_otlp, sample_events};
use core_export::config::{parse_export, OtlpConfig};
use core_export::error::{ExportError, PermanentRejection};
use core_export::http::{classify_status, is_permanent};
use core_export::pipeline::{export_otlp, ExportReport};
use core_export::types::BoxError;
use core_export::webhook::{deliver, RetryPolicy};
use std::path::Path;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const TWO_ATTEMPTS: u32 = 2;


const RETRIED: usize = 2;


const NO_CALLS: u32 = 0;


const STATUS_BAD_REQUEST: u16 = 400;


const STATUS_TIMEOUT: u16 = 408;


const STATUS_THROTTLED: u16 = 429;


const STATUS_SERVER_ERROR: u16 = 500;


const STATUS_REDIRECT: u16 = 302;


fn now() -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(FIXED_UNIX)
}


fn policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: TWO_ATTEMPTS,
        ..RetryPolicy::default()
    }
}


fn config(port: u16, buffer: &Path) -> Result<OtlpConfig, Box<dyn std::error::Error>> {
    let yaml = format!(
        "otlp:\n  endpoint: http://127.0.0.1:{port}/v1/logs\n  buffer_dir: {}\n  tenant: acme\n  allow_insecure_loopback: true\n",
        buffer.display()
    );
    Ok(parse_export(&yaml, "test")?.otlp.ok_or("no otlp")?)
}


fn run_against(status: u16, requests: usize) -> Result<(ExportReport, usize, usize), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let buffer = dir.path().join("buf");
    let sink = http_sink::spawn_http_sink(None, vec![status; requests])?;
    let report = run_otlp(
        &config(sink.port, &buffer)?,
        &sample_events(1, 0, now()?),
        &policy(),
        &mut |_delay| {},
        now()?,
    )?;
    let served = sink.bodies.join().map_err(|_panic| "sink thread panicked")??.len();
    Ok((report, list_batches(&buffer)?.len(), served))
}


#[test]
fn a_400_is_dropped_counted_and_not_retried() -> TestResult {
    let (report, buffered, served) = run_against(STATUS_BAD_REQUEST, 1)?;
    assert_eq!(
        (
            report.sent_batches,
            report.buffered_batches,
            report.rejected_batches,
            report.dropped_events
        ),
        (0, 0, 1, 0)
    );
    assert_eq!((buffered, served), (0, 1));
    Ok(())
}


#[test]
fn a_408_is_retried_then_buffered() -> TestResult {
    let (report, buffered, served) = run_against(STATUS_TIMEOUT, RETRIED)?;
    assert_eq!((report.buffered_batches, report.rejected_batches), (1, 0));
    assert_eq!((buffered, served), (1, RETRIED));
    Ok(())
}


#[test]
fn a_429_is_retried_then_buffered() -> TestResult {
    let (report, buffered, served) = run_against(STATUS_THROTTLED, RETRIED)?;
    assert_eq!((report.buffered_batches, report.rejected_batches), (1, 0));
    assert_eq!((buffered, served), (1, RETRIED));
    Ok(())
}


#[test]
fn a_500_is_retried_then_buffered() -> TestResult {
    let (report, buffered, served) = run_against(STATUS_SERVER_ERROR, RETRIED)?;
    assert_eq!((report.buffered_batches, report.rejected_batches), (1, 0));
    assert_eq!((buffered, served), (1, RETRIED));
    Ok(())
}


#[test]
fn a_3xx_is_retried_then_buffered() -> TestResult {
    let (report, buffered, served) = run_against(STATUS_REDIRECT, RETRIED)?;
    assert_eq!((report.sent_batches, report.buffered_batches, report.rejected_batches), (0, 1, 0));
    assert_eq!((buffered, served), (1, RETRIED));
    Ok(())
}


#[test]
fn a_buffered_batch_rejected_on_drain_is_deleted_and_counted() -> TestResult {
    let dir = tempdir()?;
    let buffer = dir.path().join("buf");
    let sink = http_sink::spawn_http_sink(None, vec![STATUS_BAD_REQUEST])?;
    let settings = config(sink.port, &buffer)?;
    let mut down = |_body: &str| -> Result<(), BoxError> { Err("down".into()) };
    export_otlp(
        &sample_events(1, 0, now()?),
        &settings,
        &policy(),
        &mut down,
        &mut |_delay| {},
        "h",
        now()?,
    )?;
    assert_eq!(list_batches(&buffer)?.len(), 1);
    let report = run_otlp(&settings, &[], &policy(), &mut |_delay| {}, now()?)?;
    sink.bodies.join().map_err(|_panic| "sink thread panicked")??;
    assert_eq!((report.drained_batches, report.rejected_batches), (0, 1));
    assert!(list_batches(&buffer)?.is_empty());
    Ok(())
}


#[test]
fn deliver_stops_at_once_on_a_permanent_rejection() -> TestResult {
    let mut calls = NO_CALLS;
    let mut post = |_body: &str| -> Result<(), BoxError> {
        calls += 1;
        Err(PermanentRejection { status: STATUS_BAD_REQUEST }.into())
    };
    let outcome = deliver(&policy(), &mut post, &mut |_delay| {}, "x");
    assert!(matches!(outcome, Err(ExportError::Rejected { status: STATUS_BAD_REQUEST })));
    assert_eq!(calls, 1);
    Ok(())
}


#[test]
fn only_4xx_other_than_408_and_429_is_permanent() -> TestResult {
    assert!(is_permanent(STATUS_BAD_REQUEST));
    assert!(![STATUS_TIMEOUT, STATUS_THROTTLED, STATUS_SERVER_ERROR, STATUS_REDIRECT]
        .iter()
        .any(|status| is_permanent(*status)));
    let other = classify_status("plain".into());
    assert!(other.downcast_ref::<PermanentRejection>().is_none());
    Ok(())
}
