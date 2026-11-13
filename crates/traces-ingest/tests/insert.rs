mod common;


use common::types::TestResult;
use metrics_ingest::insert::EncodeError;
use opentelemetry_proto::tonic::trace::v1::{span::SpanKind, status::StatusCode};
use serde_json::Value;
use siem_schema::traces::{render_traces_ddl, TracesRetention};
use std::collections::BTreeSet;
use traces_ingest::insert::{admit, encode_span, encode_spans, insert_statement, RefusedSpan, COLUMN_LIST, INPUT_STRUCTURE};
use traces_ingest::model::{Limits, SpanRow, SPAN_ID_BYTES, TRACE_ID_BYTES};


const NOW: u64 = 1_700_000_000_000_000_000;


const NANOS_PER_SECOND: u64 = 1_000_000_000;


const DURATION: u64 = 42;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const THIRTY_DAYS: u64 = 2_592_000;


const HOUR: u64 = 3600;


const TRACE_ID: [u8; TRACE_ID_BYTES] = [0x00, 0x0a, 0x22, 0x5c, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];


const SPAN_ID: [u8; SPAN_ID_BYTES] = [0x00, 0x0a, 0x22, 0x5c, 0xff, 0, 0, 1];


const PARENT: [u8; SPAN_ID_BYTES] = [0xff, 0x22, 0x5c, 0x0a, 0, 0, 0, 9];


const HUGE_ATTRIBUTE_BYTES: usize = 100_000;


fn row(tenant: &str) -> SpanRow {
    SpanRow {
        tenant: tenant.to_string(),
        trace_id: TRACE_ID,
        span_id: SPAN_ID,
        parent_span_id: None,
        service_name: "checkout".to_string(),
        name: "GET /cart".to_string(),
        kind: SpanKind::Server,
        start_nanos: NOW,
        end_nanos: NOW + DURATION,
        status_code: StatusCode::Ok,
        status_message: String::new(),
        attributes: vec![("host".to_string(), "a".to_string()), ("tenant".to_string(), "globex".to_string())],
        event_count: 1,
        link_count: 0,
    }
}


fn parsed(line: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(line)?)
}


fn rows_limit(rows: usize) -> Limits {
    Limits {
        max_batch_rows: rows,
        ..Limits::default()
    }
}


#[test]
fn row_encoding_snapshot() -> TestResult {
    let line = String::from_utf8(encode_span(&row("acme"))?)?;
    assert_eq!(
        line,
        "{\"attributes\":{\"host\":\"a\",\"tenant\":\"globex\"},\"duration_nanos\":42,\"event_count\":1,\"kind\":\"server\",\"link_count\":0,\
\"name\":\"GET /cart\",\"parent_span_id\":\"0000000000000000\",\"service_name\":\"checkout\",\"span_id\":\"000a225cff000001\",\
\"start\":1700000000000000000,\"status_code\":\"ok\",\"status_message\":\"\",\"tenant\":\"acme\",\"trace_id\":\"000a225cff0102030405060708090a0b\"}\n"
    );
    Ok(())
}


#[test]
fn encoded_keys_match_the_ddl_columns_and_the_input_structure() -> TestResult {
    let ddl = render_traces_ddl(&TracesRetention::default())?;
    let columns: BTreeSet<String> = ddl
        .lines()
        .filter(|line| line.starts_with("    `"))
        .filter_map(|line| line.trim().split('`').nth(1).map(str::to_string))
        .collect();
    let value = parsed(&encode_span(&row("acme"))?)?;
    let keys: BTreeSet<String> = value.as_object().ok_or("not an object")?.keys().cloned().collect();
    assert_eq!(keys, columns);
    let declared: BTreeSet<String> = INPUT_STRUCTURE
        .split(", ")
        .filter(|part| part.contains(' '))
        .filter_map(|part| part.split(' ').next().map(str::to_string))
        .collect();
    assert_eq!(declared, columns);
    Ok(())
}


#[test]
fn the_insert_column_list_follows_the_ddl_column_order() -> TestResult {
    let ddl = render_traces_ddl(&TracesRetention::default())?;
    let columns: Vec<String> = ddl
        .lines()
        .filter(|line| line.starts_with("    `"))
        .filter_map(|line| line.trim().split('`').nth(1).map(str::to_string))
        .collect();
    assert_eq!(COLUMN_LIST, columns.join(", "));
    assert!(insert_statement("ostyr", "trace_spans")?.contains(&format!("({COLUMN_LIST}) SELECT ")));
    Ok(())
}


#[test]
fn the_tenant_comes_from_the_row_and_an_attribute_named_tenant_stays_an_attribute() -> TestResult {
    let value = parsed(&encode_span(&row("acme"))?)?;
    assert_eq!(value.get("tenant"), Some(&Value::String("acme".to_string())));
    assert_eq!(value.pointer("/attributes/tenant"), Some(&Value::String("globex".to_string())));
    Ok(())
}


#[test]
fn ids_are_hex_and_a_root_span_has_an_all_zero_parent() -> TestResult {
    let root = parsed(&encode_span(&row("acme"))?)?;
    assert_eq!(root.get("parent_span_id"), Some(&Value::String("0000000000000000".to_string())));
    assert_eq!(root.get("span_id"), Some(&Value::String("000a225cff000001".to_string())));
    assert_eq!(root.get("trace_id"), Some(&Value::String("000a225cff0102030405060708090a0b".to_string())));
    let child = SpanRow {
        parent_span_id: Some(PARENT),
        ..row("acme")
    };
    assert_eq!(
        parsed(&encode_span(&child)?)?.get("parent_span_id"),
        Some(&Value::String("ff225c0a00000009".to_string()))
    );
    Ok(())
}


#[test]
fn kind_and_status_are_short_lower_case_names() -> TestResult {
    let other = SpanRow {
        kind: SpanKind::Internal,
        status_code: StatusCode::Error,
        ..row("acme")
    };
    let value = parsed(&encode_span(&other)?)?;
    assert_eq!(value.get("kind"), Some(&Value::String("internal".to_string())));
    assert_eq!(value.get("status_code"), Some(&Value::String("error".to_string())));
    Ok(())
}


#[test]
fn an_end_before_the_start_is_refused_and_a_zero_duration_is_kept() -> TestResult {
    let backwards = SpanRow {
        end_nanos: NOW - 1,
        ..row("acme")
    };
    assert_eq!(encode_span(&backwards), Err(RefusedSpan::BadDuration));
    let instant = SpanRow {
        end_nanos: NOW,
        ..row("acme")
    };
    assert_eq!(parsed(&encode_span(&instant)?)?.get("duration_nanos"), Some(&Value::from(0)));
    let encoded = encode_spans(&[backwards, instant], &Limits::default(), NOW)?;
    assert_eq!(encoded.refused.get(&RefusedSpan::BadDuration), Some(&1));
    assert_eq!(encoded.batches.iter().map(|batch| batch.rows).sum::<usize>(), 1);
    Ok(())
}


#[test]
fn the_time_window_is_checked_at_both_bounds() -> TestResult {
    let limits = Limits::default();
    let at = |start: u64| SpanRow {
        start_nanos: start,
        end_nanos: start,
        ..row("acme")
    };
    let oldest = NOW - limits.retention_seconds * NANOS_PER_SECOND;
    let newest = NOW + limits.max_future_skew_seconds * NANOS_PER_SECOND;
    assert!(admit(&at(oldest), NOW, &limits).is_ok());
    assert_eq!(admit(&at(oldest - 1), NOW, &limits), Err(RefusedSpan::TimestampOutOfRange));
    assert!(admit(&at(newest), NOW, &limits).is_ok());
    assert_eq!(admit(&at(newest + 1), NOW, &limits), Err(RefusedSpan::TimestampOutOfRange));
    let thirty_days_ago = at(NOW - THIRTY_DAYS * NANOS_PER_SECOND);
    let hour_ahead = at(NOW + HOUR * NANOS_PER_SECOND);
    let encoded = encode_spans(&[thirty_days_ago, hour_ahead, at(NOW), at(u64::MAX)], &limits, NOW)?;
    assert_eq!(encoded.refused.get(&RefusedSpan::TimestampOutOfRange), Some(&u64::try_from(THREE)?));
    assert_eq!(encoded.batches.iter().map(|batch| batch.rows).sum::<usize>(), 1);
    Ok(())
}


#[test]
fn batches_cut_at_the_row_count() -> TestResult {
    let rows: Vec<SpanRow> = (0..FIVE).map(|_| row("acme")).collect();
    assert_eq!(encode_spans(&rows, &rows_limit(FIVE), NOW)?.batches.len(), 1);
    let sizes: Vec<usize> = encode_spans(&rows, &rows_limit(FIVE - 1), NOW)?
        .batches
        .iter()
        .map(|batch| batch.rows)
        .collect();
    assert_eq!(sizes, vec![FIVE - 1, 1]);
    assert!(encode_spans(&[], &Limits::default(), NOW)?.batches.is_empty());
    Ok(())
}


#[test]
fn batches_cut_at_the_byte_size() -> TestResult {
    let line = encode_span(&row("acme"))?.len();
    let rows: Vec<SpanRow> = (0..THREE).map(|_| row("acme")).collect();
    let equal = Limits {
        max_batch_bytes: line * THREE,
        ..Limits::default()
    };
    assert_eq!(encode_spans(&rows, &equal, NOW)?.batches.len(), 1);
    let one_under = Limits {
        max_batch_bytes: line * THREE - 1,
        ..Limits::default()
    };
    let cut = encode_spans(&rows, &one_under, NOW)?;
    assert_eq!(cut.batches.iter().map(|batch| batch.rows).collect::<Vec<_>>(), vec![TWO, 1]);
    assert!(cut.batches.iter().all(|batch| batch.body.len() < line * THREE));
    Ok(())
}


#[test]
fn a_row_over_the_byte_cap_is_refused_not_truncated() -> TestResult {
    let huge = SpanRow {
        attributes: vec![("big".to_string(), "x".repeat(HUGE_ATTRIBUTE_BYTES))],
        ..row("acme")
    };
    let limits = Limits {
        max_batch_bytes: HUGE_ATTRIBUTE_BYTES,
        ..Limits::default()
    };
    let encoded = encode_spans(&[huge, row("acme")], &limits, NOW)?;
    assert_eq!(encoded.refused.get(&RefusedSpan::RowTooLarge), Some(&1));
    assert_eq!(encoded.batches.len(), 1);
    assert!(encoded
        .batches
        .iter()
        .all(|batch| batch.rows == 1 && !String::from_utf8_lossy(&batch.body).contains("xxxx")));
    let line = encode_span(&row("acme"))?.len();
    let exact = Limits {
        max_batch_bytes: line,
        ..Limits::default()
    };
    assert_eq!(encode_spans(&[row("acme")], &exact, NOW)?.batches.len(), 1);
    let under = Limits {
        max_batch_bytes: line - 1,
        ..Limits::default()
    };
    assert!(encode_spans(&[row("acme")], &under, NOW)?.batches.is_empty());
    Ok(())
}


#[test]
fn zero_batch_limits_are_errors() -> TestResult {
    let no_rows = Limits {
        max_batch_rows: 0,
        ..Limits::default()
    };
    let no_bytes = Limits {
        max_batch_bytes: 0,
        ..Limits::default()
    };
    assert_eq!(encode_spans(&[row("acme")], &no_rows, NOW).err(), Some(EncodeError::ZeroBatchRows));
    assert_eq!(encode_spans(&[row("acme")], &no_bytes, NOW).err(), Some(EncodeError::ZeroBatchBytes));
    Ok(())
}


#[test]
fn the_statement_quotes_its_identifiers_and_reads_the_input_function() -> TestResult {
    let statement = insert_statement("ostyr", "trace_spans")?;
    assert!(statement.starts_with("INSERT INTO `ostyr`.`trace_spans` (tenant, trace_id, "));
    assert!(statement.contains("unhex(trace_id)"));
    assert!(statement.contains("fromUnixTimestamp64Nano(toInt64(start), 'UTC')"));
    assert!(statement.ends_with("FORMAT JSONEachRow"));
    assert!(insert_statement("bad`db", "t").is_err());
    assert!(insert_statement("db", "").is_err());
    Ok(())
}


#[test]
fn refusals_have_fixed_names() -> TestResult {
    assert_eq!(RefusedSpan::BadDuration.to_string(), "bad_duration");
    assert_eq!(RefusedSpan::RowTooLarge.to_string(), "row_too_large");
    assert_eq!(RefusedSpan::TimestampOutOfRange.to_string(), "timestamp_out_of_range");
    let boxed: Box<dyn std::error::Error> = Box::new(RefusedSpan::BadDuration);
    assert_eq!(boxed.to_string(), "bad_duration");
    Ok(())
}
