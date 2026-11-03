#[path = "common/types.rs"]
mod types;


use core_export::buffer::list_batches;
use core_export::cli::sample_events;
use core_export::config::WebhookConfig;
use core_export::ecs::{blank_event, to_json};
use core_export::error::ExportError;
use core_export::pipeline::{export_webhook, saturation_alert, ALERT_ACTION, ALERT_SEVERITY, LABEL_BUFFER_MAX, LABEL_DROPPED};
use core_export::types::BoxError;
use core_export::webhook::{batches, RetryPolicy};
use std::cell::Cell;
use std::fs;
use std::num::ParseIntError;
use std::path::Path;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const YEAR_BEFORE_COMMON_ERA: i64 = -62_198_755_200;


const BIG_BUFFER: u64 = 1_000_000;


const EVENTS_PER_BATCH: usize = 2;


const TWO_ATTEMPTS: u32 = 2;


const FIVE_EVENTS: u64 = 5;


const TWO_EVENTS: u64 = 2;


const ONE_EVENT: u64 = 1;


const FIRST_AFTER_FIVE: u64 = 5;


const FIRST_AFTER_SEVEN: u64 = 7;


const THREE_BATCHES: usize = 3;


const FOUR_BATCHES: usize = 4;


const DROPPED_EVENTS: usize = 3;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const HOST: &str = "srv1";


fn now() -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(FIXED_UNIX)
}


fn config(dir: &Path, max_bytes: u64) -> WebhookConfig {
    WebhookConfig {
        url: "https://siem.example/hook".to_string(),
        token: None,
        batch_size: EVENTS_PER_BATCH,
        buffer_dir: dir.display().to_string(),
        buffer_max_bytes: max_bytes,
        ca_file: None,
    }
}


fn policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: TWO_ATTEMPTS,
        ..RetryPolicy::default()
    }
}


fn sequences(bodies: &[String]) -> Result<Vec<u64>, ParseIntError> {
    bodies
        .iter()
        .flat_map(|body| {
            body.split("\"sequence\":")
                .skip(1)
                .map(|rest| rest.chars().take_while(char::is_ascii_digit).collect::<String>())
                .collect::<Vec<_>>()
        })
        .map(|digits| digits.parse::<u64>())
        .collect()
}


fn expected_sequences(count: u64) -> Vec<u64> {
    (0..count).collect()
}


#[test]
fn a_reachable_target_receives_every_batch() -> TestResult {
    let dir = tempdir()?;
    let mut received = Vec::new();
    let mut post = |body: &str| -> Result<(), BoxError> {
        received.push(body.to_string());
        Ok(())
    };
    let events = sample_events(FIVE_EVENTS, 0, now()?);
    let report = export_webhook(
        &events,
        &config(dir.path(), BIG_BUFFER),
        &policy(),
        &mut post,
        &mut |_delay| {},
        HOST,
        now()?,
    )?;
    assert_eq!(
        (
            report.sent_batches,
            report.buffered_batches,
            report.drained_batches,
            report.dropped_events
        ),
        (THREE_BATCHES, 0, 0, 0)
    );
    assert!(report.alert.is_none());
    assert_eq!(sequences(&received)?, expected_sequences(FIVE_EVENTS));
    Ok(())
}


#[test]
fn a_down_target_buffers_then_the_buffer_drains_in_order_once_it_is_back() -> TestResult {
    let dir = tempdir()?;
    let buffer = dir.path().join("buffer");
    let settings = config(&buffer, BIG_BUFFER);
    let attempts = Cell::new(u32::MIN);
    let mut down = |_body: &str| -> Result<(), BoxError> {
        attempts.set(attempts.get() + 1);
        Err("connection refused".into())
    };
    let first_events = sample_events(FIVE_EVENTS, 0, now()?);
    let first = export_webhook(&first_events, &settings, &policy(), &mut down, &mut |_delay| {}, HOST, now()?)?;
    assert_eq!((first.sent_batches, first.buffered_batches, first.dropped_events), (0, THREE_BATCHES, 0));
    assert_eq!(attempts.get(), TWO_ATTEMPTS);
    let second_events = sample_events(TWO_EVENTS, FIRST_AFTER_FIVE, now()?);
    let second = export_webhook(&second_events, &settings, &policy(), &mut down, &mut |_delay| {}, HOST, now()?)?;
    assert_eq!((second.sent_batches, second.buffered_batches, second.drained_batches), (0, 1, 0));
    assert_eq!(attempts.get(), TWO_ATTEMPTS + TWO_ATTEMPTS);
    assert_eq!(list_batches(&buffer)?.len(), FOUR_BATCHES);
    let mut received = Vec::new();
    let mut up = |body: &str| -> Result<(), BoxError> {
        received.push(body.to_string());
        Ok(())
    };
    let third_events = sample_events(ONE_EVENT, FIRST_AFTER_SEVEN, now()?);
    let third = export_webhook(&third_events, &settings, &policy(), &mut up, &mut |_delay| {}, HOST, now()?)?;
    assert_eq!((third.sent_batches, third.drained_batches, third.buffered_batches), (1, FOUR_BATCHES, 0));
    assert_eq!(sequences(&received)?, expected_sequences(FIRST_AFTER_SEVEN + ONE_EVENT));
    assert!(list_batches(&buffer)?.is_empty());
    Ok(())
}


#[test]
fn a_saturated_buffer_drops_the_batch_and_raises_the_alert() -> TestResult {
    let dir = tempdir()?;
    let events = sample_events(FIVE_EVENTS, 0, now()?);
    let serialised = events.iter().map(to_json).collect::<Result<Vec<_>, _>>()?;
    let (_count, first_batch) = batches(&serialised, EVENTS_PER_BATCH).into_iter().next().ok_or("no batch")?;
    let max_bytes = first_batch.len() as u64;
    let settings = config(dir.path(), max_bytes);
    let mut down = |_body: &str| -> Result<(), BoxError> { Err("down".into()) };
    let report = export_webhook(&events, &settings, &policy(), &mut down, &mut |_delay| {}, HOST, now()?)?;
    assert_eq!((report.buffered_batches, report.dropped_events), (1, DROPPED_EVENTS));
    let alert = report.alert.ok_or("an alert is expected")?;
    assert_eq!(alert.event.action.as_deref(), Some(ALERT_ACTION));
    assert_eq!(alert.event.severity, Some(ALERT_SEVERITY));
    assert_eq!(
        alert.labels.get(LABEL_DROPPED).map(String::as_str),
        Some(DROPPED_EVENTS.to_string().as_str())
    );
    assert_eq!(
        alert.labels.get(LABEL_BUFFER_MAX).map(String::as_str),
        Some(max_bytes.to_string().as_str())
    );
    Ok(())
}


#[test]
fn the_alert_names_the_host_and_the_loss() -> TestResult {
    let alert = saturation_alert(HOST, DROPPED_EVENTS, BIG_BUFFER, now()?);
    assert_eq!(alert.host.and_then(|host| host.name).as_deref(), Some(HOST));
    assert_eq!(alert.message.as_deref(), Some("export buffer saturated, 3 event(s) dropped"));
    assert_eq!(alert.event.kind.as_deref(), Some("alert"));
    Ok(())
}


#[test]
fn local_failures_are_errors_not_a_down_target() -> TestResult {
    let dir = tempdir()?;
    let mut up = |_body: &str| -> Result<(), BoxError> { Ok(()) };
    let bad_event = blank_event(OffsetDateTime::from_unix_timestamp(YEAR_BEFORE_COMMON_ERA)?);
    let serialise = export_webhook(
        &[bad_event],
        &config(dir.path(), BIG_BUFFER),
        &policy(),
        &mut up,
        &mut |_delay| {},
        HOST,
        now()?,
    );
    assert!(matches!(serialise, Err(ExportError::Serialize(_))));
    let file = dir.path().join("file");
    fs::write(&file, "x")?;
    let mut down = |_body: &str| -> Result<(), BoxError> { Err("down".into()) };
    let one = sample_events(ONE_EVENT, 0, now()?);
    let blocked = export_webhook(&one, &config(&file, BIG_BUFFER), &policy(), &mut down, &mut |_delay| {}, HOST, now()?);
    assert!(matches!(blocked, Err(ExportError::Io { .. })));
    let corrupt = dir.path().join("corrupt");
    fs::create_dir(&corrupt)?;
    fs::write(corrupt.join("0.batch"), INVALID_UTF8)?;
    let unreadable = export_webhook(&one, &config(&corrupt, BIG_BUFFER), &policy(), &mut up, &mut |_delay| {}, HOST, now()?);
    assert!(matches!(unreadable, Err(ExportError::Io { .. })));
    Ok(())
}


#[cfg(unix)]
#[test]
fn an_unwritable_buffer_is_an_io_error_not_a_loss() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    const READ_ONLY_MODE: u32 = 0o555;
    const WRITABLE_MODE: u32 = 0o755;
    let dir = tempdir()?;
    let buffer = dir.path().join("buffer");
    fs::create_dir(&buffer)?;
    fs::set_permissions(&buffer, fs::Permissions::from_mode(READ_ONLY_MODE))?;
    let mut down = |_body: &str| -> Result<(), BoxError> { Err("down".into()) };
    let one = sample_events(ONE_EVENT, 0, now()?);
    let outcome = export_webhook(&one, &config(&buffer, BIG_BUFFER), &policy(), &mut down, &mut |_delay| {}, HOST, now()?);
    fs::set_permissions(&buffer, fs::Permissions::from_mode(WRITABLE_MODE))?;
    assert!(matches!(outcome, Err(ExportError::Io { .. })));
    Ok(())
}
