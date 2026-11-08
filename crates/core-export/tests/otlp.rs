#[path = "common/types.rs"]
mod types;


use core_export::config::OtlpConfig;
use core_export::ecs::{blank_event, to_json, EcsEvent};
use core_export::error::ExportError;
use core_export::otlp::{log_record, otlp_batches, read_token, rejected_records, MAX_TOKEN_BYTES};
use serde_json::{json, Value};
use std::fs;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const BEFORE_EPOCH: i64 = -1;


const BATCH_SIZE: usize = 2;


const FIVE_EVENTS: usize = 5;


const REJECTED: u64 = 7;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const YEAR_BEFORE_COMMON_ERA: i64 = -62_198_755_200;


fn config(tenant: Option<&str>, batch_size: usize) -> OtlpConfig {
    OtlpConfig {
        endpoint: "https://collector.example:4318/v1/logs".to_string(),
        token_file: None,
        batch_size,
        buffer_dir: "/unused".to_string(),
        buffer_max_bytes: 1,
        ca_file: None,
        service_name: "ostyr".to_string(),
        tenant: tenant.map(str::to_string),
    }
}


fn event(unix: i64, message: &str) -> Result<EcsEvent, time::error::ComponentRange> {
    Ok(EcsEvent {
        message: Some(message.to_string()),
        ..blank_event(OffsetDateTime::from_unix_timestamp(unix)?)
    })
}


#[test]
fn the_request_body_matches_the_otlp_json_shape() -> TestResult {
    let first = event(FIXED_UNIX, "hello")?;
    let batches = otlp_batches(std::slice::from_ref(&first), &config(Some("acme"), BATCH_SIZE))?;
    let (count, body) = batches.first().ok_or("no batch")?;
    assert_eq!(*count, 1);
    let expected = json!({
        "resourceLogs": [{
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": "ostyr" } },
                { "key": "tenant.id", "value": { "stringValue": "acme" } }
            ] },
            "scopeLogs": [{
                "scope": { "name": "ostyr" },
                "logRecords": [{ "timeUnixNano": "1700000000000000000", "body": { "stringValue": to_json(&first)? } }]
            }]
        }]
    });
    assert_eq!(serde_json::from_str::<Value>(body)?, expected);
    assert!(to_json(&first)?.contains("\"@timestamp\":\"2023-11-14T22:13:20Z\""));
    Ok(())
}


#[test]
fn without_a_tenant_only_the_service_name_is_an_attribute() -> TestResult {
    let batches = otlp_batches(&[event(FIXED_UNIX, "x")?], &config(None, BATCH_SIZE))?;
    let (_count, body) = batches.first().ok_or("no batch")?;
    let parsed = serde_json::from_str::<Value>(body)?;
    let attributes = parsed
        .pointer("/resourceLogs/0/resource/attributes")
        .and_then(Value::as_array)
        .ok_or("no attributes")?;
    assert_eq!(attributes.len(), 1);
    Ok(())
}


#[test]
fn batches_hold_at_most_batch_size_records_and_zero_means_one() -> TestResult {
    let events = (0..FIVE_EVENTS).map(|_| event(FIXED_UNIX, "x")).collect::<Result<Vec<_>, _>>()?;
    let counts = |size: usize| -> Result<Vec<usize>, ExportError> {
        Ok(otlp_batches(&events, &config(None, size))?
            .into_iter()
            .map(|(count, _body)| count)
            .collect())
    };
    assert_eq!(counts(BATCH_SIZE)?, vec![BATCH_SIZE, BATCH_SIZE, 1]);
    assert_eq!(counts(0)?, vec![1; FIVE_EVENTS]);
    Ok(())
}


#[test]
fn a_time_before_the_epoch_is_clamped_and_an_unserialisable_event_is_an_error() -> TestResult {
    let record = log_record(&event(BEFORE_EPOCH, "x")?)?;
    assert_eq!(record.get("timeUnixNano").and_then(Value::as_str), Some("0"));
    let bad = blank_event(OffsetDateTime::from_unix_timestamp(YEAR_BEFORE_COMMON_ERA)?);
    assert!(matches!(otlp_batches(&[bad], &config(None, 1)), Err(ExportError::Serialize(_))));
    Ok(())
}


#[test]
fn rejected_records_reads_a_number_or_a_string() -> TestResult {
    assert_eq!(rejected_records(""), 0);
    assert_eq!(rejected_records("   "), 0);
    assert_eq!(rejected_records("{}"), 0);
    assert_eq!(rejected_records("{\"partialSuccess\":{}}"), 0);
    assert_eq!(rejected_records("{\"partialSuccess\":{\"rejectedLogRecords\":7}}"), REJECTED);
    assert_eq!(
        rejected_records("{\"partialSuccess\":{\"rejectedLogRecords\":\"7\",\"errorMessage\":\"bad\"}}"),
        REJECTED
    );
    assert_eq!(rejected_records("{\"partialSuccess\":{\"rejectedLogRecords\":\"many\"}}"), 0);
    assert_eq!(rejected_records("not json"), 0);
    Ok(())
}


#[test]
fn the_token_is_trimmed_and_never_part_of_an_error() -> TestResult {
    let dir = tempdir()?;
    let good = dir.path().join("good");
    fs::write(&good, "  s3cret-token\n")?;
    assert_eq!(read_token(&good)?, "s3cret-token");
    let empty = dir.path().join("empty");
    fs::write(&empty, " \n")?;
    assert!(matches!(read_token(&empty), Err(ExportError::TokenEmpty(_))));
    let big = dir.path().join("big");
    fs::write(&big, "s3cret".repeat(MAX_TOKEN_BYTES))?;
    let too_large = read_token(&big).err().ok_or("expected an error")?;
    assert!(matches!(too_large, ExportError::TokenTooLarge { .. }));
    assert!(!too_large.to_string().contains("s3cret"));
    let binary = dir.path().join("binary");
    fs::write(&binary, INVALID_UTF8)?;
    assert!(matches!(read_token(&binary), Err(ExportError::Io { .. })));
    assert!(matches!(read_token(&dir.path().join("missing")), Err(ExportError::Io { .. })));
    assert!(matches!(read_token(dir.path()), Err(ExportError::Io { .. })));
    Ok(())
}
