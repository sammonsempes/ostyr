mod common;


use common::types::{Batches, Entries, TestResult};
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::{NewEntry, Outcome};
use core_config::error::ConfigError;
use core_config::reload::{current_config, reload, ReloadOutcome};
use siem_ingest::batcher::{backoff_delay, flush, new_batcher, push, real_sleep, system_clock, tick};
use siem_ingest::error::{IngestError, PushError, SettingsError};
use siem_ingest::model::{Batcher, Message};
use siem_ingest::nats_settings::{check_dead_letter_subject, check_name, check_nats_url};
use siem_ingest::parse::{truncate_reason, MAX_REASON_CHARS};
use siem_ingest::settings::{open_settings, settings_state, validate_settings, IngestSettings};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;


const TENANT: &str = "tenant-a";


const START: i64 = 1_800_000_000;


const EVENT: &str = r#"{"@timestamp":"2026-01-01T00:00:00Z","ecs":{"version":"8.11"},"event":{"kind":"event"}}"#;


const MESSAGE_CAP: usize = 87;


const LONG_NAME: usize = 200;


const BIG_NUMBER: u64 = 1_000_000_000_000;


const LONG_FIELD: usize = 500;


const MS_PER_SECOND: u64 = 1000;


const AGE_FACTOR: u64 = 2;


const THREE: usize = 3;


const TOKEN_TWO: u64 = 2;


const TOKEN_THREE: u64 = 3;


const TOKEN_FOUR: u64 = 4;


const TOKEN_FIVE: u64 = 5;


const SIZE_TWO: usize = 2;


const SIZE_FIVE: usize = 5;


const SIZE_EIGHT: usize = 8;


const STATE_FIELDS: usize = 30;


const BAD_BYTE: u8 = 0xff;


const FIRST_DELAY_MS: u64 = 100;


const SECOND_DELAY_MS: u64 = 200;


const HUGE_ATTEMPT: u32 = 200;


const TEN_SECONDS: i64 = 10;


pub struct Rig {
    pub dir: TempDir,
    pub batcher: Batcher,
    pub clock: Arc<AtomicI64>,
    pub batches: Batches,
    pub delays: Arc<Mutex<Vec<Duration>>>,
    pub failures_left: Arc<AtomicUsize>,
    pub entries: Entries,
}


fn event_len() -> usize {
    EVENT.len()
}


fn message(token: u64) -> Message {
    Message {
        tenant: TENANT.to_owned(),
        payload: EVENT.as_bytes().to_vec(),
        token,
    }
}


fn raw(token: u64, text: &str) -> Message {
    Message {
        tenant: TENANT.to_owned(),
        payload: text.as_bytes().to_vec(),
        token,
    }
}


fn settings_path(dir: &Path) -> std::path::PathBuf {
    dir.join("ingest.yaml")
}


fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


fn build_rig(yaml: &str, sink_failures: usize) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    replace_file(&settings_path(dir.path()), yaml)?;
    let clock = Arc::new(AtomicI64::new(START));
    let batches: Batches = Arc::new(Mutex::new(Vec::new()));
    let delays = Arc::new(Mutex::new(Vec::new()));
    let failures_left = Arc::new(AtomicUsize::new(sink_failures));
    let entries: Entries = Arc::new(Mutex::new(Vec::new()));
    let log = genesis_log(io::sink());
    let audit_entries = Arc::clone(&entries);
    let engine = open_settings(
        settings_path(dir.path()),
        Box::new(move |entry: NewEntry| {
            audit_entries.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
            append(&log, entry)
        }),
    )?;
    let sink_batches = Arc::clone(&batches);
    let sink_failures_left = Arc::clone(&failures_left);
    let sleep_delays = Arc::clone(&delays);
    let ticking = Arc::clone(&clock);
    let batcher = new_batcher(
        Arc::new(engine),
        Box::new(move |_tenant, documents| {
            sink_batches.lock().map_err(|_| "poisoned")?.push(documents.len());
            let failing = sink_failures_left
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                .is_ok();
            if failing {
                Err("sink down".into())
            } else {
                Ok(())
            }
        }),
        Box::new(move || OffsetDateTime::from_unix_timestamp(ticking.load(Ordering::SeqCst)).unwrap_or(OffsetDateTime::UNIX_EPOCH)),
        Box::new(move |delay| {
            if let Ok(mut recorded) = sleep_delays.lock() {
                recorded.push(delay);
            }
        }),
    );
    Ok(Rig {
        dir,
        batcher,
        clock,
        batches,
        delays,
        failures_left,
        entries,
    })
}


fn sink_calls(rig: &Rig) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    Ok(rig.batches.lock().map_err(|_| "poisoned")?.clone())
}


fn recorded_delays(rig: &Rig) -> Result<Vec<Duration>, Box<dyn std::error::Error>> {
    Ok(rig.delays.lock().map_err(|_| "poisoned")?.clone())
}


#[test]
fn flushes_on_message_count() -> TestResult {
    let mut rig = build_rig("max_batch_messages: 3\n", 0)?;
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    assert!(push(&mut rig.batcher, &message(TOKEN_TWO))?.is_none());
    assert!(sink_calls(&rig)?.is_empty());
    let report = push(&mut rig.batcher, &message(TOKEN_THREE))?.ok_or("no flush on the third message")?;
    assert_eq!(report.acknowledge, vec![1, TOKEN_TWO, TOKEN_THREE]);
    assert!(report.unacknowledged.is_empty());
    assert_eq!(report.delivered, THREE);
    assert_eq!(report.sink_error, None);
    assert_eq!(sink_calls(&rig)?, vec![THREE]);
    Ok(())
}


#[test]
fn flushes_on_batch_bytes() -> TestResult {
    let yaml = format!("max_message_bytes: {MESSAGE_CAP}\nmax_batch_bytes: {}\n", event_len() * SIZE_TWO);
    let mut rig = build_rig(&yaml, 0)?;
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    let report = push(&mut rig.batcher, &message(TOKEN_TWO))?.ok_or("no flush at the byte limit")?;
    assert_eq!(report.acknowledge, vec![1, TOKEN_TWO]);
    assert_eq!(sink_calls(&rig)?, vec![SIZE_TWO]);
    Ok(())
}


#[test]
fn flushes_on_age_with_a_frozen_clock() -> TestResult {
    let mut rig = build_rig("max_batch_age_seconds: 10\n", 0)?;
    assert!(tick(&mut rig.batcher).is_none());
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    rig.clock.fetch_add(TEN_SECONDS - 1, Ordering::SeqCst);
    assert!(tick(&mut rig.batcher).is_none());
    assert!(push(&mut rig.batcher, &message(TOKEN_TWO))?.is_none());
    rig.clock.fetch_add(1, Ordering::SeqCst);
    let report = tick(&mut rig.batcher).ok_or("no flush at the age limit")?;
    assert_eq!(report.acknowledge, vec![1, TOKEN_TWO]);
    assert!(tick(&mut rig.batcher).is_none());
    Ok(())
}


#[test]
fn dead_letters_are_acknowledged_without_reaching_the_sink() -> TestResult {
    let yaml = format!("max_message_bytes: {MESSAGE_CAP}\nmax_batch_messages: 5\n");
    let mut rig = build_rig(&yaml, 0)?;
    let oversize = "x".repeat(MESSAGE_CAP + 1);
    let secret_text = format!(r#"{{"@timestamp":"{}"}}"#, "s3cr3t-value".repeat(THREE));
    assert!(push(&mut rig.batcher, &raw(1, &oversize))?.is_none());
    assert!(push(&mut rig.batcher, &raw(TOKEN_TWO, "not json"))?.is_none());
    assert!(push(&mut rig.batcher, &raw(TOKEN_THREE, "{}"))?.is_none());
    assert!(push(&mut rig.batcher, &raw(TOKEN_FOUR, &secret_text))?.is_none());
    let report = push(
        &mut rig.batcher,
        &Message {
            tenant: TENANT.to_owned(),
            payload: vec![BAD_BYTE, BAD_BYTE],
            token: TOKEN_FIVE,
        },
    )?
    .ok_or("no flush on the fifth message")?;
    assert_eq!(report.acknowledge, vec![1, TOKEN_TWO, TOKEN_THREE, TOKEN_FOUR, TOKEN_FIVE]);
    assert_eq!(report.dead_letters.len(), SIZE_FIVE);
    assert_eq!(report.delivered, 0);
    assert!(sink_calls(&rig)?.is_empty());
    let reasons: Vec<&str> = report.dead_letters.iter().map(|dead| dead.reason.as_str()).collect();
    assert!(reasons.first().ok_or("no reason")?.contains("exceeds the cap"));
    assert!(reasons.iter().all(|reason| !reason.contains("s3cr3t")));
    assert!(reasons.iter().all(|reason| reason.chars().count() <= MAX_REASON_CHARS));
    Ok(())
}


#[test]
fn reason_is_truncated() -> TestResult {
    let long = "r".repeat(LONG_FIELD);
    assert_eq!(truncate_reason(&long).chars().count(), MAX_REASON_CHARS);
    assert_eq!(truncate_reason("short"), "short");
    Ok(())
}


#[test]
fn acknowledges_only_after_the_sink_accepts_following_retries() -> TestResult {
    let mut rig = build_rig("max_batch_messages: 2\nretry_attempts: 3\n", SIZE_TWO)?;
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    let report = push(&mut rig.batcher, &message(TOKEN_TWO))?.ok_or("no flush")?;
    assert_eq!(report.acknowledge, vec![1, TOKEN_TWO]);
    assert!(report.unacknowledged.is_empty());
    assert_eq!(sink_calls(&rig)?, vec![SIZE_TWO, SIZE_TWO, SIZE_TWO]);
    assert_eq!(
        recorded_delays(&rig)?,
        vec![Duration::from_millis(FIRST_DELAY_MS), Duration::from_millis(SECOND_DELAY_MS)]
    );
    assert_eq!(rig.failures_left.load(Ordering::SeqCst), 0);
    Ok(())
}


#[test]
fn hands_the_batch_back_after_the_attempt_cap() -> TestResult {
    let mut rig = build_rig("max_batch_messages: 3\nretry_attempts: 3\n", usize::MAX)?;
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    assert!(push(&mut rig.batcher, &raw(TOKEN_TWO, "bad"))?.is_none());
    let report = push(&mut rig.batcher, &message(TOKEN_THREE))?.ok_or("no flush")?;
    assert_eq!(report.unacknowledged, vec![1, TOKEN_THREE]);
    assert_eq!(report.acknowledge, vec![TOKEN_TWO]);
    assert_eq!(report.dead_letters.len(), 1);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.sink_error.as_deref(), Some("sink down"));
    assert_eq!(sink_calls(&rig)?.len(), THREE);
    assert_eq!(recorded_delays(&rig)?.len(), THREE - 1);
    assert!(flush(&mut rig.batcher).acknowledge.is_empty());
    assert_eq!(sink_calls(&rig)?.len(), THREE);
    Ok(())
}


#[test]
fn backoff_doubles_and_is_capped() -> TestResult {
    let settings = IngestSettings::default();
    assert_eq!(backoff_delay(&settings, 0), Duration::from_millis(settings.backoff_initial_ms));
    assert_eq!(
        backoff_delay(&settings, 1),
        Duration::from_millis(settings.backoff_initial_ms * SIZE_TWO as u64)
    );
    assert_eq!(backoff_delay(&settings, HUGE_ATTEMPT), Duration::from_millis(settings.backoff_max_ms));
    Ok(())
}


#[test]
fn refuses_messages_at_the_buffer_cap() -> TestResult {
    let yaml = format!(
        "max_message_bytes: {MESSAGE_CAP}\nmax_batch_bytes: {cap}\nmax_buffered_bytes: {cap}\n",
        cap = event_len() * SIZE_TWO + 1
    );
    let mut rig = build_rig(&yaml, 0)?;
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    assert!(push(&mut rig.batcher, &message(TOKEN_TWO))?.is_none());
    let refusal = push(&mut rig.batcher, &message(TOKEN_THREE))
        .err()
        .ok_or("the third message was accepted")?;
    assert!(matches!(refusal, PushError::BufferFull { buffered, cap } if buffered == event_len() * SIZE_TWO && cap == event_len() * SIZE_TWO + 1));
    assert!(refusal.to_string().contains("refused"));
    assert!(push(&mut rig.batcher, &raw(TOKEN_FOUR, "bad"))?.is_none());
    let report = flush(&mut rig.batcher);
    assert_eq!(report.acknowledge, vec![1, TOKEN_TWO, TOKEN_FOUR]);
    assert!(push(&mut rig.batcher, &message(TOKEN_THREE))?.is_none());
    Ok(())
}


#[test]
fn invalid_settings_keep_the_old_ones_and_valid_ones_apply_live() -> TestResult {
    let mut rig = build_rig("max_batch_messages: 2\n", 0)?;
    let path = settings_path(rig.dir.path());
    replace_file(&path, "max_batch_messages: 0\n")?;
    let engine = Arc::clone(&rig.batcher.settings);
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).max_batch_messages, SIZE_TWO);
    replace_file(&path, "max_batch_messages: 2\nbackoff_initial_ms: 20\nbackoff_max_ms: 10\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    replace_file(&path, "max_batch_messagez: 5\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).max_batch_messages, SIZE_TWO);
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    replace_file(&path, "max_batch_messages: 1\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    let report = push(&mut rig.batcher, &message(TOKEN_TWO))?.ok_or("the new count did not apply")?;
    assert_eq!(report.acknowledge, vec![1, TOKEN_TWO]);
    let entries = rig.entries.lock().map_err(|_| "poisoned")?;
    assert_eq!(entries.iter().filter(|entry| entry.outcome == Outcome::Denied).count(), THREE);
    assert_eq!(entries.iter().filter(|entry| entry.outcome == Outcome::Success).count(), 1);
    Ok(())
}


#[test]
fn opening_invalid_or_missing_settings_fails() -> TestResult {
    let dir = tempdir()?;
    let path = settings_path(dir.path());
    let audit = || -> Box<dyn Fn(NewEntry) -> Result<core_audit::model::Record, AuditError> + Send + Sync> {
        let log = genesis_log(io::sink());
        Box::new(move |entry| append(&log, entry))
    };
    assert!(matches!(
        open_settings(path.clone(), audit()),
        Err(IngestError::Config(ConfigError::Io { .. }))
    ));
    fs::write(&path, "retry_attempts: 0\n")?;
    let invalid = open_settings(path.clone(), audit()).err().ok_or("invalid settings opened")?;
    assert!(matches!(invalid, IngestError::Settings(SettingsError::OutOfRange { .. })));
    assert!(invalid.to_string().contains("retry_attempts"));
    fs::write(&path, "bogus: 1\n")?;
    assert!(matches!(
        open_settings(path, audit()),
        Err(IngestError::Config(ConfigError::Parse { .. }))
    ));
    Ok(())
}


#[test]
fn every_setting_is_bounded() -> TestResult {
    let defaults = IngestSettings::default();
    assert!(validate_settings(&defaults).is_ok());
    let mutations: Vec<fn(&mut IngestSettings)> = vec![
        |settings| settings.max_batch_messages = 0,
        |settings| settings.max_batch_messages = usize::MAX,
        |settings| settings.max_batch_bytes = 0,
        |settings| settings.max_batch_age_seconds = 0,
        |settings| settings.max_message_bytes = 0,
        |settings| settings.max_buffered_bytes = 0,
        |settings| settings.retry_attempts = 0,
        |settings| settings.retry_attempts = u32::MAX,
        |settings| settings.backoff_initial_ms = 0,
        |settings| settings.backoff_max_ms = BIG_NUMBER,
        |settings| settings.max_batch_bytes = settings.max_message_bytes - 1,
        |settings| settings.max_buffered_bytes = settings.max_message_bytes - 1,
        |settings| settings.backoff_max_ms = settings.backoff_initial_ms - 1,
        |settings| settings.nats_url = "nats://nats.example.test:4222".to_owned(),
        |settings| settings.nats_stream = "bad.name".to_owned(),
        |settings| settings.nats_consumer = String::new(),
        |settings| settings.nats_dead_letter_subject = "events.dead".to_owned(),
        |settings| settings.nats_fetch_deadline_ms = 0,
        |settings| settings.nats_request_timeout_ms = BIG_NUMBER,
        |settings| settings.nats_ack_wait_ms = 0,
        |settings| settings.nats_ack_wait_ms = u64::from(settings.max_batch_age_seconds) * MS_PER_SECOND * AGE_FACTOR - 1,
        |settings| settings.nats_ping_interval_ms = 0,
        |settings| settings.nats_max_headers = 0,
        |settings| settings.nats_ca_file = Some(PathBuf::new()),
        |settings| settings.nats_credentials_file = Some(PathBuf::new()),
        |settings| settings.nats_password_file = Some(PathBuf::new()),
        |settings| settings.nats_user = Some("ops".to_owned()),
        |settings| settings.nats_password_file = Some(PathBuf::from("/etc/nats.password")),
        |settings| {
            settings.nats_user = Some("ops".to_owned());
            settings.nats_password_file = Some(PathBuf::from("/etc/nats.password"));
            settings.nats_credentials_file = Some(PathBuf::from("/etc/nats.creds"));
        },
        |settings| {
            settings.nats_user = Some(String::new());
            settings.nats_password_file = Some(PathBuf::from("/etc/nats.password"));
        },
    ];
    mutations.iter().try_for_each(|mutate| -> TestResult {
        let mut settings = defaults.clone();
        mutate(&mut settings);
        let error = validate_settings(&settings).err().ok_or("an invalid setting passed")?;
        assert!(!error.to_string().is_empty());
        Ok(())
    })?;
    assert_eq!(settings_state(&defaults).len(), STATE_FIELDS);
    let with_files = IngestSettings {
        nats_ca_file: Some(PathBuf::from("/etc/ca.pem")),
        nats_credentials_file: Some(PathBuf::from("/etc/nats.creds")),
        nats_user: Some("ops".to_owned()),
        nats_password_file: Some(PathBuf::from("/etc/nats.password")),
        ..defaults
    };
    let state = settings_state(&with_files);
    assert_eq!(state.get("nats_ca_file").map(String::as_str), Some("/etc/ca.pem"));
    assert_eq!(state.get("nats_credentials_file").map(String::as_str), Some("/etc/nats.creds"));
    assert_eq!(state.get("nats_password_file").map(String::as_str), Some("/etc/nats.password"));
    assert_eq!(state.get("nats_user").map(String::as_str), Some("ops"));
    Ok(())
}


#[test]
fn system_helpers_work() -> TestResult {
    real_sleep(Duration::ZERO);
    assert!(system_clock() > OffsetDateTime::UNIX_EPOCH);
    Ok(())
}


#[test]
fn a_batch_never_mixes_tenants() -> TestResult {
    let mut rig = build_rig("max_batch_messages: 5\n", 0)?;
    assert!(push(&mut rig.batcher, &message(1))?.is_none());
    let mut foreign = message(TOKEN_TWO);
    foreign.tenant = "tenant-b".to_owned();
    let refusal = push(&mut rig.batcher, &foreign).err().ok_or("a second tenant was accepted")?;
    assert!(matches!(&refusal, PushError::OtherTenant { open, incoming } if open == TENANT && incoming == "tenant-b"));
    assert!(refusal.to_string().contains("flush it"));
    let first = flush(&mut rig.batcher);
    assert_eq!(first.tenant, TENANT);
    assert!(push(&mut rig.batcher, &foreign)?.is_none());
    let second = flush(&mut rig.batcher);
    assert_eq!(second.tenant, "tenant-b");
    assert_eq!(second.acknowledge, vec![TOKEN_TWO]);
    assert_eq!(flush(&mut rig.batcher).tenant, "");
    Ok(())
}


#[test]
fn the_sink_receives_the_batch_tenant() -> TestResult {
    let dir = tempdir()?;
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let path = settings_path(dir.path());
    replace_file(&path, "max_batch_messages: 1\n")?;
    let engine = open_settings(path, Box::new(|entry: NewEntry| append(&genesis_log(io::sink()), entry)))?;
    let mut batcher = new_batcher(
        Arc::new(engine),
        Box::new(move |tenant, _| {
            recorded.lock().map_err(|_| "poisoned")?.push(tenant.to_owned());
            Ok(())
        }),
        Box::new(system_clock),
        Box::new(real_sleep),
    );
    assert!(push(&mut batcher, &message(1))?.is_some());
    assert_eq!(*seen.lock().map_err(|_| "poisoned")?, vec![TENANT.to_owned()]);
    Ok(())
}


#[test]
fn an_oversized_sink_error_is_bounded_and_never_whole() -> TestResult {
    let dir = tempdir()?;
    let path = settings_path(dir.path());
    replace_file(&path, "max_batch_messages: 1\nretry_attempts: 2\n")?;
    let engine = open_settings(path, Box::new(|entry: NewEntry| append(&genesis_log(io::sink()), entry)))?;
    let mut batcher = new_batcher(
        Arc::new(engine),
        Box::new(|_, _| Err(format!("{}password=hunter2", "x".repeat(LONG_FIELD)).into())),
        Box::new(system_clock),
        Box::new(|_| ()),
    );
    let report = push(&mut batcher, &message(1))?.ok_or("no flush")?;
    let error = report.sink_error.ok_or("no sink error")?;
    assert_eq!(error.chars().count(), MAX_REASON_CHARS);
    assert!(!error.contains("hunter2"));
    Ok(())
}


#[test]
fn a_batch_larger_than_the_buffer_is_refused_by_validation() -> TestResult {
    let settings = IngestSettings {
        max_batch_bytes: SIZE_EIGHT + 1,
        max_buffered_bytes: SIZE_EIGHT,
        max_message_bytes: SIZE_EIGHT,
        ..IngestSettings::default()
    };
    assert!(matches!(validate_settings(&settings), Err(SettingsError::Inconsistent { .. })));
    Ok(())
}


#[test]
fn nats_urls_and_subjects_follow_the_transport_rules() -> TestResult {
    assert!(check_nats_url("tls://nats.example.test:4222", false).is_ok());
    assert!(check_nats_url("nats://localhost:4222", false).is_ok());
    assert!(check_nats_url("nats://nats.example.test:4222", true).is_ok());
    assert!(check_nats_url("nats://nats.example.test:4222", false).is_err());
    assert!(check_nats_url("tls://user:pass@nats.example.test:4222", false).is_err());
    assert!(check_nats_url("http://localhost:4222", true).is_err());
    assert!(check_nats_url("not a url", true).is_err());
    assert!(check_dead_letter_subject("dead.events").is_ok());
    assert!(check_dead_letter_subject("events.dead").is_err());
    assert!(check_dead_letter_subject("dead..events").is_err());
    assert!(check_dead_letter_subject("dead.*").is_err());
    assert!(check_dead_letter_subject(&"a".repeat(LONG_NAME)).is_err());
    assert!(check_name("nats_stream", &"a".repeat(LONG_NAME)).is_err());
    Ok(())
}
