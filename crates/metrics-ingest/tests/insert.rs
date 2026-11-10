mod common;


use common::types::TestResult;
use metrics_ingest::insert::{encode_row, encode_rows, in_range, insert_batches, moment, EncodeError, InsertError, RefusedRow};
use metrics_ingest::model::{Bucket, Limits, MetricKind, SampleRow};
use serde_json::Value;
use siem_schema::metrics::{render_metrics_ddl, MetricsRetention};
use std::collections::BTreeSet;


const STAMP: u64 = 1_700_000_000_123_456_789;


const VALUE: f64 = 2.5;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const STAMP_YEAR: i32 = 2023;


const STAMP_MONTH: u8 = 11;


const FOUR: u64 = 4;


const NANOS_PER_SECOND: u64 = 1_000_000_000;


const THIRTY_DAYS: u64 = 2_592_000;


const SIXTY_DAYS: u64 = 5_184_000;


const MAX_YEAR: i32 = 2554;


const MONTH_CHARS: usize = 7;


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
        "{\"@timestamp\":\"2023-11-14 22:13:20.123\",\"kind\":\"gauge\",\"labels\":{\"host\":\"a\",\"tenant\":\"evil\"},\"metric\":\"cpu\",\"tenant\":\"t1\",\"unit\":\"1\",\"value\":2.5}\n"
    );
    assert_eq!(moment(0).text, "1970-01-01 00:00:00.000");
    assert_eq!((moment(STAMP).year, moment(STAMP).month), (STAMP_YEAR, STAMP_MONTH));
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
    let encoded = encode_rows(&rows, &Limits::default(), STAMP)?;
    assert_eq!(encoded.batches.len(), TWO);
    let lines: Vec<Value> = encoded
        .batches
        .iter()
        .flat_map(|batch| String::from_utf8_lossy(&batch.body).lines().map(str::to_string).collect::<Vec<_>>())
        .map(|line| serde_json::from_str(&line))
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
    let exact = encode_rows(&rows, &rows_limit(FIVE), STAMP)?;
    assert_eq!(exact.batches.len(), 1);
    let over = encode_rows(&rows, &rows_limit(FIVE - 1), STAMP)?;
    let sizes: Vec<usize> = over.batches.iter().map(|batch| batch.rows).collect();
    assert_eq!(sizes, vec![FIVE - 1, 1]);
    assert!(encode_rows(&[], &Limits::default(), STAMP)?.batches.is_empty());
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
    assert_eq!(encode_rows(&rows, &equal, STAMP)?.batches.len(), 1);
    let one_under = Limits {
        max_batch_bytes: line * THREE - 1,
        ..Limits::default()
    };
    let cut = encode_rows(&rows, &one_under, STAMP)?;
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
    let encoded = encode_rows(&[row("t1", VALUE)], &limits, STAMP)?;
    assert!(encoded.batches.is_empty());
    assert_eq!(encoded.refused.get(&RefusedRow::RowTooLarge), Some(&1));
    let exact = Limits {
        max_batch_bytes: line,
        ..Limits::default()
    };
    assert_eq!(encode_rows(&[row("t1", VALUE)], &exact, STAMP)?.batches.len(), 1);
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
    let encoded = encode_rows(&rows, &Limits::default(), STAMP)?;
    assert_eq!(encoded.refused.get(&RefusedRow::NonFiniteValue), Some(&THREE.try_into()?));
    assert_eq!(encoded.batches.iter().map(|batch| batch.rows).sum::<usize>(), 1);
    assert_eq!(encode_row(&row("t1", f64::NAN)), Err(RefusedRow::NonFiniteValue));
    Ok(())
}


#[test]
fn zero_limits_are_refused() -> TestResult {
    assert_eq!(encode_rows(&[], &rows_limit(0), STAMP), Err(EncodeError::ZeroBatchRows));
    let no_bytes = Limits {
        max_batch_bytes: 0,
        ..Limits::default()
    };
    assert_eq!(encode_rows(&[], &no_bytes, STAMP), Err(EncodeError::ZeroBatchBytes));
    assert_eq!(EncodeError::ZeroBatchRows.to_string(), "max_batch_rows must be at least 1");
    assert_eq!(EncodeError::ZeroBatchBytes.to_string(), "max_batch_bytes must be at least 1");
    assert_eq!(RefusedRow::NonFiniteValue.to_string(), "non_finite_value");
    assert_eq!(RefusedRow::RowTooLarge.to_string(), "row_too_large");
    assert_eq!(RefusedRow::TimestampOutOfRange.to_string(), "timestamp_out_of_range");
    Ok(())
}


#[test]
fn failing_sender_stops_the_call() -> TestResult {
    let rows: Vec<SampleRow> = (0..THREE).map(|_| row("t1", VALUE)).collect();
    let batches = encode_rows(&rows, &rows_limit(1), STAMP)?.batches;
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


fn row_at(tenant: &str, nanos: u64) -> SampleRow {
    SampleRow {
        timestamp_nanos: nanos,
        ..row(tenant, VALUE)
    }
}


#[test]
fn timestamp_bounds_are_enforced_both_ways() -> TestResult {
    let limits = Limits::default();
    let oldest = STAMP - limits.raw_retention_seconds * NANOS_PER_SECOND;
    let newest = STAMP + limits.max_future_skew_seconds * NANOS_PER_SECOND;
    assert!(in_range(oldest, STAMP, &limits));
    assert!(!in_range(oldest - 1, STAMP, &limits));
    assert!(in_range(newest, STAMP, &limits));
    assert!(!in_range(newest + 1, STAMP, &limits));
    let rows = vec![
        row_at("t1", oldest),
        row_at("t1", oldest - 1),
        row_at("t1", newest),
        row_at("t1", newest + 1),
        row_at("t1", u64::MAX),
        row_at("t1", 0),
    ];
    let encoded = encode_rows(&rows, &limits, STAMP)?;
    assert_eq!(encoded.refused.get(&RefusedRow::TimestampOutOfRange), Some(&FOUR));
    assert_eq!(encoded.batches.iter().map(|batch| batch.rows).sum::<usize>(), TWO);
    assert_eq!(moment(u64::MAX).year, MAX_YEAR);
    Ok(())
}


#[test]
fn batches_hold_one_tenant_and_one_month() -> TestResult {
    let limits = Limits {
        raw_retention_seconds: SIXTY_DAYS,
        ..Limits::default()
    };
    let later = STAMP + THIRTY_DAYS * NANOS_PER_SECOND;
    let rows = vec![
        row_at("t1", STAMP),
        row_at("t2", later),
        row_at("t1", later),
        row_at("t2", STAMP),
        row_at("t1", STAMP),
    ];
    let encoded = encode_rows(&rows, &limits, later)?;
    assert_eq!(encoded.batches.len(), FOUR as usize);
    assert!(encoded.refused.is_empty());
    let mut sizes: Vec<usize> = encoded.batches.iter().map(|batch| batch.rows).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![1, 1, 1, TWO]);
    let apart = encoded.batches.iter().all(|batch| {
        let lines: Vec<Value> = String::from_utf8_lossy(&batch.body)
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let tenants: BTreeSet<&str> = lines.iter().filter_map(|line| line.get("tenant").and_then(Value::as_str)).collect();
        let months: BTreeSet<&str> = lines
            .iter()
            .filter_map(|line| line.get("@timestamp").and_then(Value::as_str))
            .filter_map(|text| text.get(..MONTH_CHARS))
            .collect();
        tenants.len() == 1 && months.len() == 1
    });
    assert!(apart);
    Ok(())
}
