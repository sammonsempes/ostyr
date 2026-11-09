use crate::bounds::Capture;
use crate::harness::{
    attempt, bounded, client_paths, empty_revocation, init_logging, make_platform, scoped_logging, server_paths, start_server_at, start_server_state,
    start_single_state, stop_server,
};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::services::{agent_identity, counter, session, settings};
use crate::state::{discarding_audit, envelope_source, make_audited_state, make_state, new_stored, recording_audit, recording_sink};
use crate::types::{Stored, TestResult};
use agent_channel::client::{backoff_delay, connect_channel, deliver_events, heartbeat, random_jitter, settle};
use agent_channel::error::{ChannelError, IdentityError};
use agent_channel::limits::{digest_text, lock_presence};
use agent_channel::model::{
    ChannelSettings, Delivery, BACKOFF_INITIAL_MILLIS, BACKOFF_MAX_MILLIS, MAX_LOGGED_DIGEST_BYTES, MAX_LOGGED_TEXT_CHARS, MAX_RECONNECT_ATTEMPTS,
    TRUNCATION_MARKER,
};
use agent_channel::presence::{check_silence, record_beat, watch_silence};
use agent_channel::proto::EventBatch;
use agent_channel::server::{already_logged, evict, log_outcome, refuse};
use agent_channel::tls::client_config;
use agent_channel::types::{DialFuture, EventSink, PauseFuture};
use core_audit::error::AuditError;
use core_audit::model::NewEntry;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::sleep;


const BATCHES: u64 = 5;


const FIRST_RUN_BATCHES: u64 = 2;


const HALF_CAP_MILLIS: u64 = 15_000;


const STILL_SILENT_SECONDS: u64 = 120;


const BACK_SECONDS: u64 = 180;


const BACK_AGAIN_SECONDS: u64 = 240;


const SILENT_AGAIN_SECONDS: u64 = 360;


const ACCEPTED_BEFORE_RESTART: usize = 2;


const THRESHOLD_SECONDS: u64 = 60;


const POLL_ATTEMPTS: u32 = 200;


const POLL_MILLIS: u64 = 25;


const HUGE_DIGEST_BYTES: usize = 10_000;


const LONG_URI_CHARS: usize = 10_000;


const LOG_BOUND_BYTES: usize = 1_024;


const BACKOFF_ATTEMPTS: u32 = 64;


const STALLED_PEERS: usize = 2;


const FOREIGN_SEQUENCE: u64 = 99;


fn batch(sequence: u64) -> EventBatch {
    EventBatch {
        sequence,
        ecs_json: b"{}".to_vec(),
        ..EventBatch::default()
    }
}


fn batches(count: u64) -> Vec<EventBatch> {
    (1..=count).map(batch).collect()
}


fn sequences(stored: &Stored) -> Result<Vec<u64>, ChannelError> {
    Ok(stored
        .lock()
        .map_err(|_| ChannelError::StreamEnded { unacknowledged: 0 })?
        .iter()
        .map(|(_identity, sequence)| *sequence)
        .collect())
}


fn failing_after(stored: Stored, accepted: usize) -> EventSink {
    Box::new(move |identity, event_batch| {
        let sink_stored = Arc::clone(&stored);
        Box::pin(async move {
            let mut held = sink_stored.lock().map_err(|_| "poisoned")?;
            if held.len() >= accepted {
                Err("disk full".into())
            } else {
                held.push((identity, event_batch.sequence));
                Ok(())
            }
        })
    })
}


fn recorded_actions(recorded: &Arc<Mutex<Vec<NewEntry>>>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(recorded
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .map(|entry| entry.action.clone())
        .collect())
}


#[test]
fn the_backoff_grows_and_never_exceeds_its_cap() -> TestResult {
    let jitters = [0, 1, u64::MAX, random_jitter()];
    assert!(jitters
        .iter()
        .all(|jitter| backoff_delay(0, *jitter) <= Duration::from_millis(BACKOFF_INITIAL_MILLIS)));
    assert!((0..BACKOFF_ATTEMPTS).all(|attempt| jitters
        .iter()
        .all(|jitter| backoff_delay(attempt, *jitter) <= Duration::from_millis(BACKOFF_MAX_MILLIS))));
    assert!((1..BACKOFF_ATTEMPTS).all(|attempt| backoff_delay(attempt, 0) >= backoff_delay(attempt - 1, 0)));
    assert_eq!(
        backoff_delay(BACKOFF_ATTEMPTS, HALF_CAP_MILLIS),
        Duration::from_millis(BACKOFF_MAX_MILLIS)
    );
    Ok(())
}


#[test]
fn a_clean_end_with_batches_left_counts_as_a_failure() -> TestResult {
    let delivery = Delivery {
        pending: batches(BATCHES),
        acknowledged: Vec::new(),
        rejected: Vec::new(),
        failures: 0,
        last: Ok(()),
    };
    let settled = settle(delivery, vec![1], Ok(()));
    let left = usize::try_from(BATCHES)? - 1;
    assert_eq!(settled.pending.len(), left);
    assert!(matches!(settled.last, Err(ChannelError::StreamEnded { unacknowledged }) if unacknowledged == left));
    assert_eq!(settled.failures, 0);
    let stalled = settle(settled, Vec::new(), Ok(()));
    assert_eq!(stalled.failures, 1);
    let late_error = settle(
        stalled,
        (FIRST_RUN_BATCHES..=BATCHES).collect(),
        Err(ChannelError::StreamEnded { unacknowledged: 0 }),
    );
    assert!(late_error.pending.is_empty());
    assert!(late_error.last.is_ok());
    assert_eq!(late_error.failures, 0);
    Ok(())
}


#[tokio::test]
async fn delivery_gives_up_after_the_attempt_cap_with_bounded_pauses() -> TestResult {
    init_logging()?;
    let dial_attempts = Arc::new(Mutex::new(u32::MIN));
    let counted = Arc::clone(&dial_attempts);
    let dial = move || -> DialFuture {
        let attempts = Arc::clone(&counted);
        Box::pin(async move {
            *attempts.lock().map_err(|_| ChannelError::StreamEnded { unacknowledged: 0 })? += 1;
            Err(ChannelError::NoCertificate { path: "dial".into() })
        })
    };
    let pauses = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&pauses);
    let pause = move |delay: Duration| -> PauseFuture {
        let delays = Arc::clone(&recorded);
        Box::pin(async move {
            if let Ok(mut held) = delays.lock() {
                held.push(delay);
            }
        })
    };
    let outcome = deliver_events(&dial, &pause, batches(BATCHES)).await;
    assert!(matches!(outcome, Err(ChannelError::RetriesExhausted { attempts, .. }) if attempts == MAX_RECONNECT_ATTEMPTS));
    assert_eq!(*dial_attempts.lock().map_err(|_| "poisoned")?, MAX_RECONNECT_ATTEMPTS);
    let delays = pauses.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(delays.len(), usize::try_from(MAX_RECONNECT_ATTEMPTS)? - 1);
    assert!(delays.iter().all(|delay| *delay <= Duration::from_millis(BACKOFF_MAX_MILLIS)));
    Ok(())
}


#[tokio::test]
async fn nothing_to_send_means_no_connection() -> TestResult {
    let dial = || -> DialFuture { Box::pin(async { Err(ChannelError::NoCertificate { path: "never".into() }) }) };
    let pause = |_delay: Duration| -> PauseFuture { Box::pin(async {}) };
    assert!(deliver_events(&dial, &pause, Vec::new()).await?.acknowledged.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_server_restart_mid_stream_resends_exactly_the_unacknowledged_batches() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let config = client_config(&agent)?;
    let before_restart = new_stored();
    let after_restart = new_stored();
    let first_state = make_state(
        ChannelSettings::default(),
        failing_after(Arc::clone(&before_restart), ACCEPTED_BEFORE_RESTART),
        envelope_source(Vec::new()),
    );
    let first = start_server_state(&paths, empty_revocation(&paths)?, first_state).await?;
    let address = first.address;
    let dial = move || -> DialFuture {
        let dial_config = Arc::clone(&config);
        Box::pin(async move { connect_channel(address, dial_config, SERVER_NAME).await })
    };
    let (delay_sender, mut delay_receiver) = mpsc::unbounded_channel::<Duration>();
    let gate = Arc::new(Notify::new());
    let pause_gate = Arc::clone(&gate);
    let pause = move |delay: Duration| -> PauseFuture {
        let waiting = Arc::clone(&pause_gate);
        let announced = delay_sender.send(delay).is_ok();
        Box::pin(async move {
            if announced {
                waiting.notified().await;
            }
        })
    };
    let delivery = tokio::spawn(async move { deliver_events(&dial, &pause, batches(BATCHES)).await });
    let delay = bounded(delay_receiver.recv()).await?.ok_or("the client never paused")?;
    assert!(delay <= Duration::from_millis(BACKOFF_MAX_MILLIS));
    stop_server(first).await?;
    let second_state = make_state(
        ChannelSettings::default(),
        recording_sink(Arc::clone(&after_restart)),
        envelope_source(Vec::new()),
    );
    let second = start_server_at(&paths, empty_revocation(&paths)?, second_state, &address.to_string()).await?;
    gate.notify_one();
    let acknowledged = bounded(delivery).await???.acknowledged;
    assert_eq!(acknowledged, (1..=BATCHES).collect::<Vec<u64>>());
    assert_eq!(sequences(&before_restart)?, (1..=FIRST_RUN_BATCHES).collect::<Vec<u64>>());
    assert_eq!(sequences(&after_restart)?, (FIRST_RUN_BATCHES + 1..=BATCHES).collect::<Vec<u64>>());
    assert!(delay_receiver.try_recv().is_err());
    stop_server(second).await
}


#[test]
fn an_agent_silent_past_the_threshold_gets_one_record_and_one_back_record() -> TestResult {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let state = make_audited_state(
        settings(|base| base.silence_threshold_seconds = THRESHOLD_SECONDS),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        recording_audit(Arc::clone(&recorded)),
    );
    let start = Instant::now();
    let identity = agent_identity();
    record_beat(&state, &identity, start);
    assert_eq!(check_silence(&state, start + Duration::from_secs(THRESHOLD_SECONDS)), 0);
    assert_eq!(check_silence(&state, start + Duration::from_secs(THRESHOLD_SECONDS + 1)), 1);
    assert_eq!(check_silence(&state, start + Duration::from_secs(STILL_SILENT_SECONDS)), 0);
    assert_eq!(recorded_actions(&recorded)?, vec!["agent.silent"]);
    record_beat(&state, &identity, start + Duration::from_secs(BACK_SECONDS));
    record_beat(&state, &identity, start + Duration::from_secs(BACK_AGAIN_SECONDS));
    assert_eq!(recorded_actions(&recorded)?, vec!["agent.silent", "agent.back"]);
    assert_eq!(check_silence(&state, start + Duration::from_secs(SILENT_AGAIN_SECONDS)), 1);
    assert_eq!(recorded_actions(&recorded)?, vec!["agent.silent", "agent.back", "agent.silent"]);
    let entries = recorded.lock().map_err(|_| "poisoned")?;
    let first = entries.first().ok_or("no record")?;
    assert_eq!((first.tenant.as_str(), first.target.as_str()), ("acme", "agent-1"));
    assert_eq!(first.parameters.get("silent_seconds").map(String::as_str), Some("61"));
    Ok(())
}


#[test]
fn a_failing_audit_log_does_not_stop_the_silence_check() -> TestResult {
    init_logging()?;
    let state = make_audited_state(
        settings(|base| base.silence_threshold_seconds = 0),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        Box::new(|_entry| Err(AuditError::LogPoisoned)),
    );
    let start = Instant::now();
    record_beat(&state, &agent_identity(), start);
    assert_eq!(check_silence(&state, start + Duration::from_secs(1)), 1);
    record_beat(&state, &agent_identity(), start);
    Ok(())
}


#[tokio::test]
async fn a_heartbeat_through_the_channel_is_recorded() -> TestResult {
    let state = make_state(ChannelSettings::default(), recording_sink(new_stored()), envelope_source(Vec::new()));
    let running = session(Arc::clone(&state)).await?;
    assert!(lock_presence(&state).is_empty());
    bounded(heartbeat(running.channel.clone(), "test")).await??;
    assert!(lock_presence(&state).get(&agent_identity()).is_some_and(|presence| !presence.silent));
    crate::services::finish_session(running).await
}


#[tokio::test(start_paused = true)]
async fn the_watch_records_a_silent_agent_and_stops_on_shutdown() -> TestResult {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let state = make_audited_state(
        settings(|base| {
            base.silence_threshold_seconds = 0;
            base.silence_check_interval_seconds = 1;
        }),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        recording_audit(Arc::clone(&recorded)),
    );
    record_beat(&state, &agent_identity(), Instant::now());
    sleep(Duration::from_millis(POLL_MILLIS)).await;
    let (stop, stopped) = oneshot::channel::<()>();
    let watching = tokio::spawn(watch_silence(Arc::clone(&state), async move {
        if let Err(error) = stopped.await {
            tracing::warn!(%error, "stop sender dropped");
        }
    }));
    let mut attempts = 0;
    while recorded_actions(&recorded)?.is_empty() && attempts < POLL_ATTEMPTS {
        sleep(Duration::from_millis(POLL_MILLIS)).await;
        attempts += 1;
    }
    assert_eq!(recorded_actions(&recorded)?, vec!["agent.silent"]);
    stop.send(()).map_err(|()| "watch already stopped")?;
    bounded(watching).await??;
    Ok(())
}


#[tokio::test]
async fn a_peer_stalling_in_the_handshake_is_dropped_at_the_timeout() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let state = make_state(ChannelSettings::default(), recording_sink(new_stored()), envelope_source(Vec::new()));
    let server = start_single_state(&paths, empty_revocation(&paths)?, Arc::clone(&state)).await?;
    let _stalled = TcpStream::connect(server.address).await?;
    tokio::time::pause();
    let served = server.handle.await?;
    assert!(matches!(served, Err(ChannelError::HandshakeTimeout { .. })));
    assert_eq!(counter(&state.counters.handshake_timeouts), 1);
    Ok(())
}


#[tokio::test]
async fn authenticated_connections_above_the_global_cap_are_dropped_and_the_slot_is_given_back() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let state = make_audited_state(
        settings(|base| base.max_total_connections = 1),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    );
    let server = start_server_state(&paths, empty_revocation(&paths)?, Arc::clone(&state)).await?;
    let held = bounded(connect_channel(server.address, client_config(&agent)?, SERVER_NAME)).await??;
    bounded(heartbeat(held.clone(), "test")).await??;
    assert!(bounded(attempt(server.address, &agent)).await?.is_err());
    assert_eq!(counter(&state.counters.connections_capped), 1);
    drop(held);
    let mut attempts = 0;
    let mut reply = bounded(attempt(server.address, &agent)).await?;
    while reply.is_err() && attempts < POLL_ATTEMPTS {
        sleep(Duration::from_millis(POLL_MILLIS)).await;
        reply = bounded(attempt(server.address, &agent)).await?;
        attempts += 1;
    }
    assert!(reply.is_ok());
    stop_server(server).await
}


#[tokio::test]
async fn an_agent_connects_while_stalled_peers_fill_every_handshake_slot() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let state = make_audited_state(
        settings(|base| base.max_pending_handshakes = STALLED_PEERS),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    );
    let server = start_server_state(&paths, empty_revocation(&paths)?, Arc::clone(&state)).await?;
    let mut oldest = TcpStream::connect(server.address).await?;
    let newest = TcpStream::connect(server.address).await?;
    sleep(Duration::from_millis(POLL_MILLIS)).await;
    assert!(bounded(attempt(server.address, &agent)).await?.is_ok());
    assert_eq!(counter(&state.counters.handshakes_evicted), 1);
    let mut buffer = [u8::MIN; 1];
    let read = bounded(oldest.read(&mut buffer)).await?;
    assert!(matches!(read, Ok(0) | Err(_)));
    drop(newest);
    stop_server(server).await
}


#[test]
fn a_foreign_or_repeated_acknowledgement_is_no_progress_and_the_delivery_gives_up() -> TestResult {
    let delivery = Delivery {
        pending: batches(BATCHES),
        acknowledged: Vec::new(),
        rejected: Vec::new(),
        failures: 0,
        last: Ok(()),
    };
    let foreign = (0..MAX_RECONNECT_ATTEMPTS).fold(delivery, |current, _attempt| {
        settle(current, vec![FOREIGN_SEQUENCE, FOREIGN_SEQUENCE], Ok(()))
    });
    assert_eq!(foreign.failures, MAX_RECONNECT_ATTEMPTS);
    assert_eq!(foreign.pending.len(), usize::try_from(BATCHES)?);
    assert!(foreign.acknowledged.is_empty());
    let once = settle(foreign, vec![1], Ok(()));
    assert_eq!(once.failures, 0);
    let repeated = settle(once, vec![1], Ok(()));
    assert_eq!(repeated.failures, 1);
    assert_eq!(repeated.acknowledged, vec![1]);
    Ok(())
}


#[test]
fn a_reported_digest_is_cut_before_it_is_encoded() -> TestResult {
    assert_eq!(digest_text(&[u8::MAX]), "ff");
    let cut = digest_text(&vec![0; HUGE_DIGEST_BYTES]);
    assert_eq!(cut.len(), MAX_LOGGED_TEXT_CHARS + TRUNCATION_MARKER.len());
    assert!(cut.ends_with(TRUNCATION_MARKER));
    let exact = digest_text(&[0; MAX_LOGGED_DIGEST_BYTES]);
    assert_eq!(exact.len(), MAX_LOGGED_TEXT_CHARS);
    Ok(())
}


#[test]
fn refusals_are_logged_once_and_a_bad_uri_is_bounded() -> TestResult {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt().with_writer(move || writer.clone()).with_ansi(false).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let refused = refuse(IdentityError::BadUri(format!("urn:{}\nforged", "x".repeat(LONG_URI_CHARS))));
    assert!(already_logged(&refused));
    let logged = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.len() < LOG_BOUND_BYTES);
    assert!(logged.contains(TRUNCATION_MARKER));
    assert_eq!(logged.lines().count(), 1);
    captured.lock().map_err(|_| "poisoned")?.clear();
    log_outcome(Err(refused));
    log_outcome(Err(ChannelError::Revoked { serial: "01".into() }));
    log_outcome(Err(ChannelError::TooManyConnections {
        tenant: "acme".into(),
        agent_id: "agent-1".into(),
    }));
    log_outcome(Ok(()));
    assert!(captured.lock().map_err(|_| "poisoned")?.is_empty());
    assert!(!already_logged(&ChannelError::NoCertificate { path: "x".into() }));
    log_outcome(Err(ChannelError::NoCertificate { path: "x".into() }));
    assert!(!captured.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[test]
fn evicting_a_handshake_that_already_finished_is_counted_and_harmless() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = crate::services::recording_state(ChannelSettings::default());
    let (sender, receiver) = oneshot::channel();
    drop(receiver);
    evict(Some(sender), &state);
    evict(None, &state);
    assert_eq!(counter(&state.counters.handshakes_evicted), 1);
    Ok(())
}


#[test]
fn a_size_refusal_quarantines_the_first_unacknowledged_batch_and_other_errors_do_not() -> TestResult {
    let _logging = scoped_logging();
    let fresh = |count: u64| Delivery {
        pending: batches(count),
        acknowledged: Vec::new(),
        rejected: Vec::new(),
        failures: 0,
        last: Ok(()),
    };
    let refused = |code: tonic::Code| Err(ChannelError::Status(Box::new(tonic::Status::new(code, "refused"))));
    let out_of_range = settle(fresh(BATCHES), vec![1], refused(tonic::Code::OutOfRange));
    assert_eq!(
        out_of_range.rejected.iter().map(|batch| batch.sequence).collect::<Vec<_>>(),
        vec![FIRST_RUN_BATCHES]
    );
    assert_eq!(out_of_range.pending.len(), usize::try_from(BATCHES - FIRST_RUN_BATCHES)?);
    assert_eq!(out_of_range.failures, 0);
    let exhausted = settle(fresh(1), Vec::new(), refused(tonic::Code::ResourceExhausted));
    assert!(exhausted.rejected.is_empty());
    assert_eq!(exhausted.pending.len(), 1);
    assert_eq!(exhausted.failures, 1);
    let internal = settle(fresh(1), Vec::new(), refused(tonic::Code::Internal));
    assert!(internal.rejected.is_empty());
    assert_eq!(internal.failures, 1);
    let nothing_pending = settle(fresh(0), Vec::new(), refused(tonic::Code::OutOfRange));
    assert!(nothing_pending.rejected.is_empty());
    Ok(())
}
