use crate::services::agent_identity;
use crate::state::{envelope_source, make_audited_state, make_live_state, new_stored, recording_audit, recording_sink};
use crate::types::TestResult;
use agent_channel::error::SettingsError;
use agent_channel::limits::open_slot;
use agent_channel::model::{ChannelSettings, Identity, SlotKind, DEFAULT_MAX_STREAMS_PER_AGENT};
use agent_channel::presence::{record_beat, watch_silence};
use agent_channel::settings::{open_settings_engine, resize_total, settings_of, settings_state, validate_settings};
use core_audit::model::{NewEntry, Outcome};
use core_config::reload::{reload, ReloadContext, ReloadOutcome};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::sync::{oneshot, Semaphore};
use tokio::time::sleep;


const SETTINGS_FILE: &str = "settings.yaml";


const FIRST_BOUND: usize = 1;


const SECOND_BOUND: usize = 2;


const CAPACITY: usize = 4;


const SHRUNK: usize = 1;


const FIELD_COUNT: usize = 14;


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "agent-channel".to_owned(),
        tenant: "acme".to_owned(),
        module: "agent-channel".to_owned(),
        target: SETTINGS_FILE.to_owned(),
        request_id: "settings-reload".to_owned(),
    }
}


fn agent() -> Identity {
    Identity {
        tenant: "acme".to_owned(),
        agent_id: "agent-1".to_owned(),
    }
}


fn write_bound(dir: &Path, bound: usize) -> std::io::Result<()> {
    fs::write(dir.join(SETTINGS_FILE), format!("max_connections_per_agent: {bound}\n"))
}


#[test]
fn a_reload_changes_the_bound_for_new_connections_and_is_audited() -> TestResult {
    let dir = tempdir()?;
    write_bound(dir.path(), FIRST_BOUND)?;
    let recorded: Arc<Mutex<Vec<NewEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let (engine, shared) = open_settings_engine(dir.path().join(SETTINGS_FILE), recording_audit(Arc::clone(&recorded)), context())?;
    let state = make_live_state(shared);
    let first = open_slot(&state, &agent(), SlotKind::Connection)?;
    assert!(open_slot(&state, &agent(), SlotKind::Connection).is_err());
    write_bound(dir.path(), SECOND_BOUND)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(settings_of(&state).max_connections_per_agent, SECOND_BOUND);
    let second = open_slot(&state, &agent(), SlotKind::Connection)?;
    assert!(open_slot(&state, &agent(), SlotKind::Connection).is_err());
    drop((first, second));
    let entries = recorded.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(entries.len(), 1);
    assert!(entries
        .iter()
        .all(|entry| entry.action == "config.reload" && entry.outcome == Outcome::Success));
    assert!(entries.iter().all(|entry| entry
        .parameters
        .get("diff")
        .is_some_and(|diff| diff.contains("max_connections_per_agent"))));
    Ok(())
}


#[test]
fn an_invalid_reload_keeps_the_old_settings() -> TestResult {
    let dir = tempdir()?;
    write_bound(dir.path(), SECOND_BOUND)?;
    let recorded: Arc<Mutex<Vec<NewEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let (engine, shared) = open_settings_engine(dir.path().join(SETTINGS_FILE), recording_audit(Arc::clone(&recorded)), context())?;
    let state = make_live_state(shared);
    fs::write(dir.path().join(SETTINGS_FILE), "max_message_bytes: 0\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("max_message_bytes")));
    fs::write(dir.path().join(SETTINGS_FILE), "unknown_bound: 3\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(settings_of(&state).max_connections_per_agent, SECOND_BOUND);
    assert_eq!(settings_of(&state).max_message_bytes, ChannelSettings::default().max_message_bytes);
    let entries = recorded.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(entries.len(), SECOND_BOUND);
    assert!(entries.iter().all(|entry| entry.outcome == Outcome::Denied));
    Ok(())
}


#[test]
fn the_first_load_must_be_valid() -> TestResult {
    let dir = tempdir()?;
    let audit = || recording_audit(Arc::new(Mutex::new(Vec::new())));
    assert!(matches!(
        open_settings_engine(dir.path().join(SETTINGS_FILE), audit(), context()),
        Err(SettingsError::Config(_))
    ));
    fs::write(dir.path().join(SETTINGS_FILE), "max_total_connections: 0\n")?;
    assert!(matches!(
        open_settings_engine(dir.path().join(SETTINGS_FILE), audit(), context()),
        Err(SettingsError::Invalid(_))
    ));
    Ok(())
}


#[test]
fn validation_names_every_bad_field() -> TestResult {
    assert!(validate_settings(&ChannelSettings::default()).is_ok());
    let bad = ChannelSettings {
        max_message_bytes: 0,
        max_total_connections: usize::MAX,
        ..ChannelSettings::default()
    };
    let message = validate_settings(&bad).err().ok_or("accepted")?.to_string();
    assert!(message.contains("max_message_bytes") && message.contains("max_total_connections"));
    Ok(())
}


#[test]
fn the_state_has_one_line_per_field() -> TestResult {
    let state = settings_state(&ChannelSettings::default());
    let expected = DEFAULT_MAX_STREAMS_PER_AGENT.to_string();
    assert_eq!(state.get("channel_settings.max_streams_per_agent"), Some(&expected));
    assert_eq!(state.len(), FIELD_COUNT);
    Ok(())
}


#[test]
fn the_total_cap_grows_and_shrinks() -> TestResult {
    let semaphore = Semaphore::new(CAPACITY);
    assert_eq!(resize_total(&semaphore, CAPACITY, CAPACITY), CAPACITY);
    assert_eq!(resize_total(&semaphore, CAPACITY, CAPACITY + SECOND_BOUND), CAPACITY + SECOND_BOUND);
    assert_eq!(semaphore.available_permits(), CAPACITY + SECOND_BOUND);
    let held = semaphore.try_acquire_many(u32::try_from(CAPACITY)?)?;
    assert_eq!(resize_total(&semaphore, CAPACITY + SECOND_BOUND, SHRUNK), CAPACITY);
    drop(held);
    assert_eq!(semaphore.available_permits(), CAPACITY);
    Ok(())
}


const SLOW_INTERVAL_SECONDS: u64 = 1000;


const FAST_INTERVAL_SECONDS: u64 = 1;


const SLOW_TICK_MILLIS: u64 = 1_000_500;


const FAST_TICK_MILLIS: u64 = 1_000;


#[test]
fn zero_bounds_are_refused() -> TestResult {
    let bad = ChannelSettings {
        max_streams_per_agent: 0,
        max_connections_per_agent: 0,
        max_inflight_per_agent: 0,
        max_requests_per_window: 0,
        silence_threshold_seconds: 0,
        silence_check_interval_seconds: 0,
        ..ChannelSettings::default()
    };
    let message = validate_settings(&bad).err().ok_or("accepted")?.to_string();
    [
        "max_streams_per_agent",
        "max_connections_per_agent",
        "max_inflight_per_agent",
        "max_requests_per_window",
        "silence_threshold_seconds",
        "silence_check_interval_seconds",
    ]
    .iter()
    .for_each(|name| assert!(message.contains(name)));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_silence_interval_follows_a_reload() -> TestResult {
    let recorded: Arc<Mutex<Vec<NewEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let state = make_audited_state(
        ChannelSettings {
            silence_threshold_seconds: 0,
            silence_check_interval_seconds: SLOW_INTERVAL_SECONDS,
            ..ChannelSettings::default()
        },
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        recording_audit(Arc::clone(&recorded)),
    );
    record_beat(&state, &agent_identity(), Instant::now());
    let (stop, stopped) = oneshot::channel::<()>();
    let watching = tokio::spawn(watch_silence(Arc::clone(&state), async move {
        if let Err(error) = stopped.await {
            tracing::warn!(%error, "stop sender dropped");
        }
    }));
    tokio::task::yield_now().await;
    state.settings.store(Arc::new(ChannelSettings {
        silence_threshold_seconds: 0,
        silence_check_interval_seconds: FAST_INTERVAL_SECONDS,
        ..ChannelSettings::default()
    }));
    sleep(Duration::from_millis(SLOW_TICK_MILLIS)).await;
    record_beat(&state, &agent_identity(), Instant::now());
    sleep(Duration::from_millis(FAST_TICK_MILLIS)).await;
    stop.send(()).map_err(|()| "watch already stopped")?;
    watching.await?;
    let actions: Vec<String> = recorded
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .map(|entry| entry.action.clone())
        .collect();
    assert_eq!(actions, vec!["agent.silent", "agent.back", "agent.silent"]);
    Ok(())
}
