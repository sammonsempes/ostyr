mod common;


use common::types::TestResult;
use metrics_ingest::insert::{encode_row, encode_rows, insert_batches, timestamp_text, EncodeError, InsertError, RefusedRow};
use metrics_ingest::model::{Bucket, Limits, MetricKind, SampleRow};
use serde_json::Value;
use siem_schema::metrics::{render_metrics_ddl, MetricsRetention};
use std::collections::BTreeSet;


const STAMP: u64 = 1_700_000_000_123_456_789;


const VALUE: f64 = 2.5;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


fn row(tenant: &str, value: f64) -> SampleRow {
    SampleRow {
        tenant: tenant.to_string(),
        name: "cpu".to_string(),
        unit: "1".to_string(),
        kind: MetricKind::Gauge,
        monotonic: false,
        labels: vec![("host".to_string(), "a".to_string()), ("tenant".to_string(), "evil".to_string())],
        timestamp_nanos: STAMP,
        value,
        buckets: vec![Bucket {
            upper_bound: f64::INFINITY,
            count: 1,
        }],
    }
}


fn rows_limit(rows: usize) -> Limits {
    Limits {
        max_batch_rows: rows,
        ..Limits::default()
    }
}


#[test]
fn row_encoding_snapshot() -> TestResult {
    let line = String::from_utf8(encode_row(&row("t1", VALUE))?)?;
    assert_eq!(
        line,
        "{\"@timestamp\":\"1700000000.123\",\"kind\":\"gauge\",\"labels\":{\"host\":\"a\",\"tenant\":\"evil\"},\"metric\":\"cpu\",\"tenant\":\"t1\",\"unit\":\"1\",\"value\":2.5}\n"
    );
    assert_eq!(timestamp_text(0), "0.000");
    Ok(())
}


#[test]
fn kinds_are_named() -> TestResult {
    let counter = SampleRow {
        kind: MetricKind::Counter,
        ..row("t1", VALUE)
    };
    let histogram = SampleRow {
        kind: MetricKind::Histogram,
        ..row("t1", VALUE)
    };
    assert!(String::from_utf8(encode_row(&counter)?)?.contains("\"counter\""));
    assert!(String::from_utf8(encode_row(&histogram)?)?.contains("\"histogram\""));
    Ok(())
}


#[test]
fn encoded_keys_match_the_ddl_columns() -> TestResult {
    let statements = render_metrics_ddl(&MetricsRetention::default())?;
    let raw = statements.first().ok_or("no statement")?;
    let columns: BTreeSet<String> = raw
        .lines()
        .filter(|line| line.starts_with("    `"))
        .filter_map(|line| line.trim().split('`').nth(1).map(str::to_string))
        .collect();
    let value: Value = serde_json::from_slice(&encode_row(&row("t1", VALUE))?)?;
    let keys: BTreeSet<String> = value.as_object().ok_or("not an object")?.keys().cloned().collect();
    assert_eq!(keys, columns);
    Ok(())
}


#[test]
fn tenant_comes_from_the_row_and_tenants_stay_apart() -> TestResult {
    let rows = vec![row("t1", VALUE), row("t2", VALUE)];
    let encoded = encode_rows(&rows, &Limits::default())?;
    let batch = encoded.batches.first().ok_or("no batch")?;
    let lines: Vec<Value> = String::from_utf8(batch.body.clone())?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let tenants: Vec<&str> = lines.iter().filter_map(|line| line.get("tenant").and_then(Value::as_str)).collect();
    assert_eq!(tenants, vec!["t1", "t2"]);
    assert!(lines
        .iter()
        .all(|line| line.pointer("/labels/tenant") == Some(&Value::String("evil".to_string()))));
    Ok(())
}


#[test]
fn batches_cut_at_the_row_count() -> TestResult {
    let rows: Vec<SampleRow> = (0..FIVE).map(|_| row("t1", VALUE)).collect();
    let exact = encode_rows(&rows, &rows_limit(FIVE))?;
    assert_eq!(exact.batches.len(), 1);
    let over = encode_rows(&rows, &rows_limit(FIVE - 1))?;
    let sizes: Vec<usize> = over.batches.iter().map(|batch| batch.rows).collect();
    assert_eq!(sizes, vec![FIVE - 1, 1]);
    assert!(encode_rows(&[], &Limits::default())?.batches.is_empty());
    Ok(())
}


#[test]
fn batches_cut_at_the_byte_size() -> TestResult {
    let line = encode_row(&row("t1", VALUE))?.len();
    let rows: Vec<SampleRow> = (0..THREE).map(|_| row("t1", VALUE)).collect();
    let equal = Limits {
        max_batch_bytes: line * THREE,
        ..Limits::default()
    };
    assert_eq!(encode_rows(&rows, &equal)?.batches.len(), 1);
    let one_under = Limits {
        max_batch_bytes: line * THREE - 1,
        ..Limits::default()
    };
    let cut = encode_rows(&rows, &one_under)?;
    let sizes: Vec<usize> = cut.batches.iter().map(|batch| batch.rows).collect();
    assert_eq!(sizes, vec![TWO, 1]);
    assert!(cut.batches.iter().all(|batch| batch.body.len() < line * THREE));
    Ok(())
}


#[test]
fn oversized_row_is_refused_and_counted() -> TestResult {
    let line = encode_row(&row("t1", VALUE))?.len();
    let limits = Limits {
        max_batch_bytes: line - 1,
        ..Limits::default()
    };
    let encoded = encode_rows(&[row("t1", VALUE)], &limits)?;
    assert!(encoded.batches.is_empty());
    assert_eq!(encoded.refused.get(&RefusedRow::RowTooLarge), Some(&1));
    let exact = Limits {
        max_batch_bytes: line,
        ..Limits::default()
    };
    assert_eq!(encode_rows(&[row("t1", VALUE)], &exact)?.batches.len(), 1);
    Ok(())
}


#[test]
fn non_finite_values_are_refused_per_row() -> TestResult {
    let rows = vec![
        row("t1", f64::NAN),
        row("t1", f64::INFINITY),
        row("t1", f64::NEG_INFINITY),
        row("t1", VALUE),
    ];
    let encoded = encode_rows(&rows, &Limits::default())?;
    assert_eq!(encoded.refused.get(&RefusedRow::NonFiniteValue), Some(&THREE.try_into()?));
    assert_eq!(encoded.batches.iter().map(|batch| batch.rows).sum::<usize>(), 1);
    assert_eq!(encode_row(&row("t1", f64::NAN)), Err(RefusedRow::NonFiniteValue));
    Ok(())
}


#[test]
fn zero_limits_are_refused() -> TestResult {
    assert_eq!(encode_rows(&[], &rows_limit(0)), Err(EncodeError::ZeroBatchRows));
    let no_bytes = Limits {
        max_batch_bytes: 0,
        ..Limits::default()
    };
    assert_eq!(encode_rows(&[], &no_bytes), Err(EncodeError::ZeroBatchBytes));
    assert_eq!(EncodeError::ZeroBatchRows.to_string(), "max_batch_rows must be at least 1");
    assert_eq!(EncodeError::ZeroBatchBytes.to_string(), "max_batch_bytes must be at least 1");
    assert_eq!(RefusedRow::NonFiniteValue.to_string(), "non_finite_value");
    assert_eq!(RefusedRow::RowTooLarge.to_string(), "row_too_large");
    Ok(())
}


#[test]
fn failing_sender_stops_the_call() -> TestResult {
    let rows: Vec<SampleRow> = (0..THREE).map(|_| row("t1", VALUE)).collect();
    let batches = encode_rows(&rows, &rows_limit(1))?.batches;
    let mut seen = 0;
    let all = insert_batches(&batches, |_body| {
        seen += 1;
        Ok(())
    });
    assert_eq!(all, Ok(THREE));
    let mut calls = 0;
    let first = insert_batches(&batches, |_body| {
        calls += 1;
        Err("secret-token".to_string())
    });
    assert_eq!(first, Err(InsertError { sent: 0 }));
    assert_eq!(calls, 1);
    let mut count = 0;
    let later = insert_batches(&batches, |_body| {
        count += 1;
        if count < THREE {
            Ok(())
        } else {
            Err("secret-token".to_string())
        }
    });
    let failure = later.err().ok_or("expected failure")?;
    assert_eq!(failure.sent, THREE - 1);
    assert!(!failure.to_string().contains("secret"));
    assert_eq!(failure.to_string(), "metric batch insert failed after 2 batches sent");
    assert_eq!(seen, THREE);
    Ok(())
}
