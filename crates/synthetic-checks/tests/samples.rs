#![cfg(unix)]


#[path = "common/ch_stub.rs"]
mod ch_stub;
#[path = "common/private.rs"]
mod private;
#[path = "common/types.rs"]
mod types;


use core_pg::scope::tenant_scope;
use metrics_ingest::insert::{Batch, RefusedRow};
use metrics_ingest::settings::{load_settings, MetricsSettings};
use private::write_private;
use serde_json::Value;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use synthetic_checks::model::CheckKind;
use synthetic_checks::samples::{
    deliver, log_refused, nanos_of, post_batches, probed_of, record, sample_rows, send_round, wall_nanos, SampleReport, SampleTotals, SendFailure,
    CATEGORY_ENCODE, CATEGORY_REFUSED, CATEGORY_SEND, CATEGORY_SENDER, CATEGORY_SETTINGS, MAX_SAMPLE_SEND_MS, METRIC_NAME,
};
use synthetic_checks::types::{Clock, WallNanos};
use tempfile::tempdir;
use tracing::dispatcher::with_default;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use types::TestResult;


const WALL_NOW: u64 = 1_700_000_000_000_000_000;


const NANOS_PER_SECOND: u64 = 1_000_000_000;


const TWO_YEARS_SECONDS: u64 = 63_072_000;


const PASSWORD: &str = "SAMPLEPW-77aa";


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


const THREE: usize = 3;


const UP: f64 = 1.0;


const DOWN: f64 = 0.0;


const DIGEST_HEX_LEN: usize = 64;


const FIVE_SECONDS_NANOS: u64 = 5_000_000_000;


const ONE_MINUTE_SECONDS: u64 = 60;


const SHORT_TIMEOUT_MS: u64 = 2000;


const TWO: u64 = 2;


const REAL_REQUESTS: usize = 2;


const LONG_TIMEOUT_MS: u64 = 300_000;


const ELAPSED_AT_CAP: Duration = Duration::from_millis(MAX_SAMPLE_SEND_MS);


const ELAPSED_BEFORE_CAP: Duration = Duration::from_millis(MAX_SAMPLE_SEND_MS - 1_000);


const MESSAGE_GUARD: Duration = Duration::from_secs(600);


fn wall() -> Option<u64> {
    Some(WALL_NOW)
}


fn no_time() -> Option<u64> {
    None
}


fn zero() -> Duration {
    Duration::ZERO
}


fn write_settings(dir: &Path, port: u16, timeout_ms: u64, limits: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    write_private(&dir.join("ch.pass"), PASSWORD.as_bytes())?;
    let file = dir.join("clickhouse.yaml");
    fs::write(
        &file,
        format!(
            "url: http://127.0.0.1:{port}\nuser: synthetic\npassword_file: {}\ndatabase: ostyr\ntable: metric_samples\ntimeout_ms: {timeout_ms}\n{limits}",
            dir.join("ch.pass").display()
        ),
    )?;
    Ok(file)
}


fn three_probes(wall_fn: &WallNanos) -> Vec<synthetic_checks::samples::Probed> {
    vec![
        probed_of("web", CheckKind::Http, true, wall_fn),
        probed_of("db", CheckKind::Tcp, false, wall_fn),
        probed_of("dns-1", CheckKind::Dns, true, wall_fn),
    ]
}


fn json_lines(body: &[u8]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(body.to_vec())?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?)
}


fn text_of<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str)
}


fn label_of<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    row.get("labels").and_then(|labels| labels.get(key)).and_then(Value::as_str)
}


fn offline_settings(dir: &Path, limits: &str) -> Result<MetricsSettings, Box<dyn std::error::Error>> {
    Ok(load_settings(&write_settings(dir, 1, LONG_TIMEOUT_MS, limits)?)?)
}


#[test]
fn a_round_of_three_results_gives_three_rows_with_metric_value_labels_and_tenant() -> TestResult {
    let dir = tempdir()?;
    let settings = offline_settings(dir.path(), "")?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let bodies = Mutex::new(Vec::new());
    let report = deliver(
        &settings,
        &rows,
        WALL_NOW,
        &zero,
        &|_settings: &MetricsSettings, _elapsed: &Clock, batches: &[Batch]| {
            bodies
                .lock()
                .map_err(|_poisoned| SendFailure { sent: 0, category: "lock" })?
                .extend(batches.iter().map(|batch| batch.body.clone()));
            Ok(batches.len())
        },
    );
    assert_eq!(
        report,
        SampleReport {
            sent: THREE as u64,
            ..SampleReport::default()
        }
    );
    let held = bodies.lock().map_err(|_poisoned| "poisoned")?.concat();
    let lines = json_lines(&held)?;
    assert_eq!(lines.len(), THREE);
    let expected = [("web", "http", UP), ("db", "tcp", DOWN), ("dns-1", "dns", UP)];
    expected.iter().try_for_each(|(check, kind, value)| -> TestResult {
        let row = lines.iter().find(|line| label_of(line, "check") == Some(*check)).ok_or("row missing")?;
        assert_eq!(text_of(row, "tenant"), Some("acme"));
        assert_eq!(text_of(row, "metric"), Some(METRIC_NAME));
        assert_eq!(text_of(row, "unit"), Some("1"));
        assert_eq!(text_of(row, "kind"), Some("gauge"));
        assert_eq!(label_of(row, "kind"), Some(*kind));
        assert_eq!(label_of(row, "location"), Some("paris"));
        assert_eq!(row.get("value").and_then(Value::as_f64), Some(*value));
        assert!(text_of(row, "@timestamp").is_some_and(|stamp| stamp.starts_with("2023-11-14")), "{row}");
        Ok(())
    })?;
    Ok(())
}


#[test]
fn a_name_with_a_bidi_control_is_written_as_its_full_digest_identity() -> TestResult {
    let scope = tenant_scope("acme")?;
    let probed = vec![probed_of("web\u{202e}x", CheckKind::Http, true, &wall)];
    let rows = sample_rows(&scope, "paris", &probed);
    let identity = rows
        .first()
        .and_then(|row| row.labels.iter().find(|(key, _value)| key == "check"))
        .map(|(_key, value)| value.clone())
        .ok_or("no identity")?;
    assert!(identity.starts_with('#'));
    assert_eq!(identity.len(), 1 + DIGEST_HEX_LEN);
    assert!(identity.chars().skip(1).all(|character| character.is_ascii_hexdigit()));
    Ok(())
}


#[test]
fn rows_carry_the_wall_time_and_a_row_outside_the_window_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings = offline_settings(dir.path(), "")?;
    let scope = tenant_scope("acme")?;
    let monotonic = || Some(FIVE_SECONDS_NANOS);
    let wall_rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let monotonic_rows = sample_rows(&scope, "paris", &three_probes(&monotonic));
    assert!(wall_rows.iter().all(|row| row.timestamp_nanos == WALL_NOW));
    let sender = |_settings: &MetricsSettings, _elapsed: &Clock, batches: &[Batch]| Ok(batches.len());
    assert_eq!(deliver(&settings, &wall_rows, WALL_NOW, &zero, &sender).refused, 0);
    let stale = deliver(&settings, &monotonic_rows, WALL_NOW, &zero, &sender);
    assert_eq!((stale.sent, stale.refused), (0, THREE as u64));
    Ok(())
}


#[test]
fn rows_without_a_wall_time_are_left_out_and_counted_refused_by_the_round() -> TestResult {
    let dir = tempdir()?;
    let file = write_settings(dir.path(), 1, LONG_TIMEOUT_MS, "")?;
    let scope = tenant_scope("acme")?;
    let probed = three_probes(&no_time);
    let rows = sample_rows(&scope, "paris", &probed);
    assert!(rows.is_empty());
    let report = send_round(
        &file,
        &rows,
        probed.len() as u64,
        &no_time,
        &zero,
        &|_settings: &MetricsSettings, _elapsed: &Clock, batches: &[Batch]| Ok(batches.len()),
    );
    assert_eq!(
        report,
        SampleReport {
            refused: THREE as u64,
            ..SampleReport::default()
        }
    );
    let mixed = vec![probed_of("web", CheckKind::Http, true, &wall)];
    let live_rows = sample_rows(&scope, "paris", &mixed);
    let clockless = send_round(
        &file,
        &live_rows,
        0,
        &no_time,
        &zero,
        &|_settings: &MetricsSettings, _elapsed: &Clock, batches: &[Batch]| Ok(batches.len()),
    );
    assert_eq!((clockless.sent, clockless.refused), (0, 1));
    Ok(())
}


#[test]
fn the_clock_reading_before_the_epoch_gives_none_and_the_real_clock_a_time() -> TestResult {
    let later = SystemTime::now() + Duration::from_secs(ONE_MINUTE_SECONDS);
    let before = UNIX_EPOCH.duration_since(later).err().ok_or("no error")?;
    assert_eq!(nanos_of(Err(before)), None);
    assert_eq!(nanos_of(Ok(Duration::from_secs(1))), Some(NANOS_PER_SECOND));
    assert_eq!(nanos_of(Ok(Duration::MAX)), None);
    assert!(wall_nanos().is_some_and(|now| now > WALL_NOW));
    Ok(())
}


#[test]
fn a_failing_second_batch_loses_the_unsent_rows_and_is_not_retried() -> TestResult {
    let dir = tempdir()?;
    let settings = offline_settings(dir.path(), "limits: {max_batch_rows: 1}\n")?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let calls = Mutex::new(usize::default());
    let failing = |_settings: &MetricsSettings, _elapsed: &Clock, batches: &[Batch]| {
        *calls.lock().map_err(|_poisoned| SendFailure { sent: 0, category: "lock" })? += 1;
        assert_eq!(batches.len(), THREE);
        Err(SendFailure {
            sent: 1,
            category: CATEGORY_SEND,
        })
    };
    let report = deliver(&settings, &rows, WALL_NOW, &zero, &failing);
    assert_eq!(
        report,
        SampleReport {
            sent: 1,
            failed: TWO,
            refused: 0,
            category: Some(CATEGORY_SEND)
        }
    );
    assert_eq!(*calls.lock().map_err(|_poisoned| "poisoned")?, 1);
    Ok(())
}


#[test]
fn a_zero_batch_limit_and_an_all_refused_round_send_nothing() -> TestResult {
    let dir = tempdir()?;
    let mut settings = offline_settings(dir.path(), "")?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let never = |_settings: &MetricsSettings, _elapsed: &Clock, _batches: &[Batch]| Err(SendFailure { sent: 0, category: "called" });
    settings.limits.max_batch_rows = 0;
    let encode = deliver(&settings, &rows, WALL_NOW, &zero, &never);
    assert_eq!((encode.failed, encode.category), (THREE as u64, Some(CATEGORY_ENCODE)));
    settings.limits.max_batch_rows = 1;
    let future = WALL_NOW + TWO_YEARS_SECONDS * NANOS_PER_SECOND;
    let refused = deliver(&settings, &rows, future, &zero, &never);
    assert_eq!(
        (refused.sent, refused.failed, refused.refused, refused.category),
        (0, 0, THREE as u64, None)
    );
    Ok(())
}


#[test]
fn the_round_reads_the_settings_once_and_an_unreadable_file_loses_the_rows() -> TestResult {
    let dir = tempdir()?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let sender = |_settings: &MetricsSettings, _elapsed: &Clock, batches: &[Batch]| Ok(batches.len());
    let missing = send_round(&dir.path().join("absent.yaml"), &rows, 0, &wall, &zero, &sender);
    assert_eq!((missing.failed, missing.category), (THREE as u64, Some(CATEGORY_SETTINGS)));
    let file = write_settings(dir.path(), 1, LONG_TIMEOUT_MS, "")?;
    let seen = Mutex::new(u64::default());
    let capped = send_round(
        &file,
        &rows,
        0,
        &wall,
        &zero,
        &|settings: &MetricsSettings, _e: &Clock, batches: &[Batch]| {
            *seen.lock().map_err(|_poisoned| SendFailure { sent: 0, category: "lock" })? = settings.timeout_ms;
            Ok(batches.len())
        },
    );
    assert_eq!(capped.sent, THREE as u64);
    assert_eq!(*seen.lock().map_err(|_poisoned| "poisoned")?, MAX_SAMPLE_SEND_MS);
    fs::write(
        &file,
        fs::read_to_string(&file)?.replace(&LONG_TIMEOUT_MS.to_string(), &SHORT_TIMEOUT_MS.to_string()),
    )?;
    let small = send_round(
        &file,
        &rows,
        0,
        &wall,
        &zero,
        &|settings: &MetricsSettings, _e: &Clock, batches: &[Batch]| {
            *seen.lock().map_err(|_poisoned| SendFailure { sent: 0, category: "lock" })? = settings.timeout_ms;
            Ok(batches.len())
        },
    );
    assert_eq!(small.sent, THREE as u64);
    assert_eq!(*seen.lock().map_err(|_poisoned| "poisoned")?, SHORT_TIMEOUT_MS);
    Ok(())
}


#[test]
fn the_real_send_posts_every_batch_and_keeps_no_target_or_password_in_the_body() -> TestResult {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let file = write_settings(
        dir.path(),
        listener.local_addr()?.port(),
        LONG_TIMEOUT_MS,
        "limits: {max_batch_rows: 1}\n",
    )?;
    let (stub, requests) = ch_stub::serve(listener, vec![OK, OK, OK])?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let report = send_round(&file, &rows, 0, &wall, &zero, &post_batches);
    assert_eq!(
        report,
        SampleReport {
            sent: THREE as u64,
            ..SampleReport::default()
        }
    );
    assert_eq!(ch_stub::finish(stub)?, THREE);
    let seen: Vec<String> = (0..THREE)
        .map(|_request| requests.recv_timeout(MESSAGE_GUARD))
        .collect::<Result<_, _>>()?;
    assert!(seen.iter().all(|request| request.contains("metric_samples")));
    assert!(seen.iter().all(|request| request.contains(METRIC_NAME)));
    assert!(seen
        .iter()
        .all(|request| request.split("\r\n\r\n").nth(1).is_some_and(|body| !body.contains(PASSWORD))));
    Ok(())
}


#[test]
fn a_server_error_on_the_second_batch_counts_the_unsent_rows_and_a_bad_password_file_the_sender() -> TestResult {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let file = write_settings(
        dir.path(),
        listener.local_addr()?.port(),
        LONG_TIMEOUT_MS,
        "limits: {max_batch_rows: 1}\n",
    )?;
    let (stub, requests) = ch_stub::serve(listener, vec![OK, SERVER_ERROR, OK])?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let report = send_round(&file, &rows, 0, &wall, &zero, &post_batches);
    assert_eq!(
        report,
        SampleReport {
            sent: 1,
            failed: TWO,
            refused: 0,
            category: Some(CATEGORY_SEND)
        }
    );
    assert_eq!(ch_stub::finish(stub)?, REAL_REQUESTS);
    let seen: Vec<String> = requests.try_iter().collect();
    assert_eq!(seen.len(), REAL_REQUESTS);
    fs::remove_file(dir.path().join("ch.pass"))?;
    let settings = load_settings(&file)?;
    let batches = [Batch { body: Vec::new(), rows: 1 }];
    assert_eq!(
        post_batches(&settings, &zero, &batches),
        Err(SendFailure {
            sent: 0,
            category: CATEGORY_SENDER
        })
    );
    Ok(())
}


#[test]
fn a_send_deadline_is_capped_at_the_constant_whatever_the_settings_allow() -> TestResult {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let file = write_settings(dir.path(), listener.local_addr()?.port(), LONG_TIMEOUT_MS, "")?;
    let (stub, requests) = ch_stub::serve(listener, vec![OK])?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let spent = send_round(&file, &rows, 0, &wall, &|| ELAPSED_AT_CAP, &post_batches);
    assert_eq!((spent.sent, spent.failed, spent.category), (0, THREE as u64, Some(CATEGORY_SEND)));
    assert!(requests.try_recv().is_err());
    let left = send_round(&file, &rows, 0, &wall, &|| ELAPSED_BEFORE_CAP, &post_batches);
    assert_eq!(left.sent, THREE as u64);
    assert_eq!(ch_stub::finish(stub)?, 1);
    assert!(requests.recv_timeout(MESSAGE_GUARD).is_ok());
    Ok(())
}


#[test]
fn recording_a_round_sums_the_totals() -> TestResult {
    let totals = SampleTotals::default();
    record(
        &totals,
        &SampleReport {
            sent: THREE as u64,
            ..SampleReport::default()
        },
    );
    record(&totals, &lost_two());
    assert_eq!(totals.sent.load(Ordering::Relaxed), THREE as u64);
    assert_eq!(totals.failed.load(Ordering::Relaxed), TWO);
    assert_eq!(totals.refused.load(Ordering::Relaxed), 1);
    Ok(())
}


fn lost_two() -> SampleReport {
    SampleReport {
        sent: 0,
        failed: TWO,
        refused: 1,
        category: Some(CATEGORY_SEND),
    }
}


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn captured(action: impl FnOnce()) -> String {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&buffer);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(BoxMakeWriter::new(move || Capture(Arc::clone(&sink))))
            .finish(),
    );
    with_default(&dispatch, action);
    let text = String::from_utf8_lossy(&buffer.lock().unwrap_or_else(PoisonError::into_inner)).into_owned();
    text
}


#[test]
fn the_refusal_lines_name_a_category_and_a_reason_and_never_none() -> TestResult {
    let dir = tempdir()?;
    let scope = tenant_scope("acme")?;
    let rows = sample_rows(&scope, "paris", &three_probes(&wall));
    let missing = dir.path().join("absent.yaml");
    let settings_line = captured(|| {
        send_round(&missing, &rows, 0, &wall, &zero, &post_batches);
    });
    assert!(settings_line.contains("the metrics settings were refused, samples lost"));
    assert!(settings_line.contains("reason="));
    let refused_line = captured(|| log_refused(RefusedRow::TimestampOutOfRange, TWO));
    assert!(refused_line.contains("metric samples refused by the encoder"));
    assert!(refused_line.contains("name=\"TimestampOutOfRange\""));
    assert!(refused_line.contains("count=2"));
    let record_line = captured(|| {
        record(
            &SampleTotals::default(),
            &SampleReport {
                refused: 1,
                ..SampleReport::default()
            },
        )
    });
    assert!(record_line.contains(&format!("category=\"{CATEGORY_REFUSED}\"")));
    assert!(!record_line.contains("none"));
    Ok(())
}
