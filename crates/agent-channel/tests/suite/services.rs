use crate::harness::{bounded, client_paths, make_platform, scoped_logging, server_paths, start_server_state, stop_server, Platform};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::state::{envelope_source, failing_sink, make_state, new_stored, recording_sink};
use crate::types::{Stored, TestResult};
use agent_channel::client::{connect_channel, heartbeat, open_event_stream, push_events, run_commands, status_error};
use agent_channel::error::ChannelError;
use agent_channel::limits::{admit_request, check_claim, claim_matches, count_request, fresh_load, open_stream};
use agent_channel::model::{ChannelSettings, CommandVerdict, Identity, DEFAULT_MAX_MESSAGE_BYTES};
use agent_channel::proto::{BeatRequest, CommandReport, EventBatch, SubscribeRequest};
use agent_channel::services::{beat, open_push, report, subscribe};
use agent_channel::tls::client_config;
use agent_channel::types::{CommandSource, SharedClientConfig, SharedState};
use agent_command::keys::open_keys_engine;
use agent_command::model::{Action, Command, KeyClass, Sequences, NONCE_LENGTH};
use agent_command::sign::{memory_signer, sign_command};
use agent_command::verify::open_verifier_with;
use core_audit::log::{append, genesis_log};
use core_config::reload::ReloadContext;
use data_encoding::HEXLOWER;
use ed25519_dalek::SigningKey;
use futures_util::{stream, StreamExt};
use std::error::Error;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};
use tracing::subscriber::DefaultGuard;


const FIRST: u64 = 1;


const SECOND: u64 = 2;


const THIRD: u64 = 3;


const NOW: u64 = 1_700_000_000;


const LIFETIME: u64 = 60;


const KEY_LIFETIME: u64 = 3_600;


const KEY_SEED: u8 = 7;


const SEED_LENGTH: usize = 32;


const DIGEST_LENGTH: usize = 32;


const KEY_ID: &str = "routine-1";


const OVERSIZED_BYTES: usize = 4_096;


const SMALL_LIMIT: usize = 1_024;


const FLOOD_BATCHES: u64 = 10;


const FLOOD_LIMIT: u32 = 3;


const LONG_WINDOW_SECONDS: u64 = 3_600;


const BATCH_COUNT: u64 = 3;


pub fn agent_identity() -> Identity {
    Identity {
        tenant: "acme".to_string(),
        agent_id: "agent-1".to_string(),
    }
}


fn batch(sequence: u64) -> EventBatch {
    EventBatch {
        sequence,
        ecs_json: b"{}".to_vec(),
        ..EventBatch::default()
    }
}


fn identified<Message>(message: Message) -> Request<Message> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(agent_identity());
    request
}


pub fn counter(value: &AtomicU64) -> u64 {
    value.load(Ordering::Relaxed)
}


pub fn settings(change: impl FnOnce(&mut ChannelSettings)) -> ChannelSettings {
    let mut base = ChannelSettings::default();
    change(&mut base);
    base
}


pub struct Session {
    pub channel: Channel,
    pub config: SharedClientConfig,
    pub server: crate::harness::RunningServer,
    _dir: tempfile::TempDir,
    _logging: DefaultGuard,
}


pub async fn session(state: SharedState) -> Result<Session, Box<dyn Error>> {
    let logging = scoped_logging();
    let dir = tempdir()?;
    let platform: Platform = make_platform()?;
    let server = start_server_state(
        &server_paths(dir.path(), &platform)?,
        crate::harness::empty_revocation(&server_paths(dir.path(), &platform)?)?,
        state,
    )
    .await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let config = client_config(&paths)?;
    let channel = bounded(connect_channel(server.address, Arc::clone(&config), SERVER_NAME)).await??;
    Ok(Session {
        channel,
        config,
        server,
        _dir: dir,
        _logging: logging,
    })
}


pub async fn finish_session(session: Session) -> TestResult {
    stop_server(session.server).await
}


pub fn status_code(outcome: Result<impl std::fmt::Debug, ChannelError>) -> Option<Code> {
    match outcome {
        Err(ChannelError::Status(status)) => Some(status.code()),
        _ => None,
    }
}


pub fn recording_state(settings: ChannelSettings) -> (SharedState, Stored) {
    let stored = new_stored();
    (
        make_state(settings, recording_sink(Arc::clone(&stored)), envelope_source(Vec::new())),
        stored,
    )
}


fn stored_count(stored: &Stored) -> Result<usize, Box<dyn Error>> {
    Ok(stored.lock().map_err(|_| "poisoned")?.len())
}


#[tokio::test]
async fn events_are_acknowledged_after_the_sink_accepted_them() -> TestResult {
    let (state, stored) = recording_state(ChannelSettings::default());
    let session = session(Arc::clone(&state)).await?;
    let acknowledged = bounded(push_events(session.channel.clone(), (1..=BATCH_COUNT).map(batch).collect())).await??;
    assert_eq!(acknowledged, vec![FIRST, SECOND, THIRD]);
    assert_eq!(stored_count(&stored)?, usize::try_from(THIRD)?);
    assert_eq!(
        stored.lock().map_err(|_| "poisoned")?.first().map(|entry| entry.0.clone()),
        Some(agent_identity())
    );
    assert_eq!(counter(&state.counters.events_acknowledged), BATCH_COUNT);
    finish_session(session).await
}


#[tokio::test]
async fn a_failing_sink_acknowledges_nothing() -> TestResult {
    let state = make_state(ChannelSettings::default(), failing_sink(), envelope_source(Vec::new()));
    let session = session(Arc::clone(&state)).await?;
    let outcome = bounded(push_events(session.channel.clone(), vec![batch(FIRST), batch(SECOND)])).await?;
    assert_eq!(status_code(outcome), Some(Code::Unavailable));
    assert_eq!(counter(&state.counters.events_acknowledged), 0);
    finish_session(session).await
}


#[tokio::test]
async fn a_payload_naming_another_agent_is_refused() -> TestResult {
    let (state, stored) = recording_state(ChannelSettings::default());
    let session = session(Arc::clone(&state)).await?;
    let foreign = EventBatch {
        agent_id: "agent-2".to_string(),
        ..batch(1)
    };
    let outcome = bounded(push_events(session.channel.clone(), vec![foreign])).await?;
    assert_eq!(status_code(outcome), Some(Code::PermissionDenied));
    assert_eq!(counter(&state.counters.identity_mismatch), 1);
    assert_eq!(stored_count(&stored)?, 0);
    finish_session(session).await
}


#[tokio::test]
async fn an_oversized_stream_message_is_refused_and_counted() -> TestResult {
    let (state, stored) = recording_state(settings(|base| base.max_message_bytes = SMALL_LIMIT));
    let session = session(Arc::clone(&state)).await?;
    let large = EventBatch {
        ecs_json: vec![0; OVERSIZED_BYTES],
        ..batch(1)
    };
    let outcome = bounded(push_events(session.channel.clone(), vec![large])).await?;
    assert_eq!(status_code(outcome), Some(Code::OutOfRange));
    assert_eq!(counter(&state.counters.oversized), 1);
    assert_eq!(stored_count(&stored)?, 0);
    finish_session(session).await
}


#[tokio::test]
async fn an_oversized_unary_message_is_refused_and_counted() -> TestResult {
    let (state, _stored) = recording_state(settings(|base| base.max_message_bytes = SMALL_LIMIT));
    let session = session(Arc::clone(&state)).await?;
    let outcome = bounded(heartbeat(session.channel.clone(), &"x".repeat(OVERSIZED_BYTES))).await?;
    assert_eq!(status_code(outcome), Some(Code::OutOfRange));
    assert_eq!(counter(&state.counters.oversized), 1);
    finish_session(session).await
}


#[tokio::test]
async fn a_batch_flood_is_refused_and_counted() -> TestResult {
    let (state, stored) = recording_state(settings(|base| {
        base.max_requests_per_window = FLOOD_LIMIT;
        base.rate_window_seconds = LONG_WINDOW_SECONDS;
    }));
    let session = session(Arc::clone(&state)).await?;
    let outcome = bounded(push_events(session.channel.clone(), (1..=FLOOD_BATCHES).map(batch).collect())).await?;
    assert_eq!(status_code(outcome), Some(Code::ResourceExhausted));
    assert_eq!(counter(&state.counters.rate_limited), 1);
    assert_eq!(stored_count(&stored)?, usize::try_from(FLOOD_LIMIT - 1)?);
    finish_session(session).await
}


#[tokio::test]
async fn a_heartbeat_flood_is_refused_and_counted() -> TestResult {
    let (state, _stored) = recording_state(settings(|base| {
        base.max_requests_per_window = 1;
        base.rate_window_seconds = LONG_WINDOW_SECONDS;
    }));
    let session = session(Arc::clone(&state)).await?;
    let first = bounded(heartbeat(session.channel.clone(), "test")).await??;
    let second = bounded(heartbeat(session.channel.clone(), "test")).await?;
    assert_eq!(first.interval_seconds, ChannelSettings::default().heartbeat_interval_seconds);
    assert_eq!(status_code(second), Some(Code::ResourceExhausted));
    assert_eq!(counter(&state.counters.rate_limited), 1);
    finish_session(session).await
}


#[tokio::test]
async fn a_second_stream_above_the_bound_is_refused_and_counted() -> TestResult {
    let (state, _stored) = recording_state(settings(|base| base.max_streams_per_agent = 1));
    let session = session(Arc::clone(&state)).await?;
    let mut held = bounded(open_event_stream(
        session.channel.clone(),
        stream::iter(vec![batch(1)]).chain(stream::pending()),
    ))
    .await??;
    let first = bounded(held.next()).await?;
    assert_eq!(first.map(|item| item.map(|ack| ack.sequence).ok()), Some(Some(1)));
    let outcome = bounded(push_events(session.channel.clone(), vec![batch(SECOND)])).await?;
    assert_eq!(status_code(outcome), Some(Code::ResourceExhausted));
    assert_eq!(counter(&state.counters.stream_limited), 1);
    finish_session(session).await
}


#[test]
fn a_stream_slot_is_given_back_when_the_permit_is_dropped() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|base| base.max_streams_per_agent = 1));
    let first = open_stream(&state, &agent_identity())?;
    assert!(open_stream(&state, &agent_identity()).is_err());
    drop(first);
    assert!(open_stream(&state, &agent_identity()).is_ok());
    Ok(())
}


#[test]
fn the_rate_window_restarts_when_it_has_elapsed() -> TestResult {
    let start = Instant::now();
    let window = Duration::from_secs(1);
    let mut load = fresh_load(start);
    assert!(count_request(&mut load, start, window, 1));
    assert!(!count_request(&mut load, start, window, 1));
    assert!(count_request(&mut load, start + window, window, 1));
    Ok(())
}


#[test]
fn admission_refuses_above_the_rate() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|base| base.max_requests_per_window = 0));
    assert_eq!(
        admit_request(&state, &agent_identity()).err().map(|status| status.code()),
        Some(Code::ResourceExhausted)
    );
    Ok(())
}


#[test]
fn claims_are_checked_against_the_certificate_only() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(ChannelSettings::default());
    let identity = agent_identity();
    assert!(claim_matches("", "acme"));
    assert!(claim_matches("acme", "acme"));
    assert!(!claim_matches("other", "acme"));
    assert!(check_claim(&state, &identity, "", "").is_ok());
    assert!(check_claim(&state, &identity, "acme", "agent-1").is_ok());
    assert!(check_claim(&state, &identity, "acme", "agent-2").is_err());
    assert!(check_claim(&state, &identity, "other", "agent-1").is_err());
    assert_eq!(counter(&state.counters.identity_mismatch), SECOND);
    Ok(())
}


#[tokio::test]
async fn handlers_refuse_a_request_without_identity_or_with_another_name() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(ChannelSettings::default());
    let unauthenticated = subscribe(Arc::clone(&state), Request::new(SubscribeRequest::default())).await;
    assert_eq!(unauthenticated.err().map(|status| status.code()), Some(Code::Unauthenticated));
    let unauthenticated_report = report(Arc::clone(&state), Request::new(CommandReport::default())).await;
    assert_eq!(unauthenticated_report.err().map(|status| status.code()), Some(Code::Unauthenticated));
    let foreign_subscribe = subscribe(
        Arc::clone(&state),
        identified(SubscribeRequest {
            agent_id: "agent-2".to_string(),
            ..SubscribeRequest::default()
        }),
    )
    .await;
    assert_eq!(foreign_subscribe.err().map(|status| status.code()), Some(Code::PermissionDenied));
    let foreign_report = report(
        Arc::clone(&state),
        identified(CommandReport {
            tenant: "other".to_string(),
            ..CommandReport::default()
        }),
    )
    .await;
    assert_eq!(foreign_report.err().map(|status| status.code()), Some(Code::PermissionDenied));
    let foreign_beat = beat(
        Arc::clone(&state),
        identified(BeatRequest {
            agent_id: "agent-2".to_string(),
            ..BeatRequest::default()
        }),
    )
    .await;
    assert_eq!(foreign_beat.err().map(|status| status.code()), Some(Code::PermissionDenied));
    assert_eq!(counter(&state.counters.identity_mismatch), THIRD);
    Ok(())
}


#[tokio::test]
async fn reports_are_counted_by_verdict() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(ChannelSettings::default());
    report(
        Arc::clone(&state),
        identified(CommandReport {
            accepted: true,
            ..CommandReport::default()
        }),
    )
    .await?;
    report(Arc::clone(&state), identified(CommandReport::default())).await?;
    assert_eq!(
        (counter(&state.counters.commands_accepted), counter(&state.counters.commands_refused)),
        (1, 1)
    );
    Ok(())
}


#[tokio::test]
async fn a_subscription_above_the_stream_bound_is_refused() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|base| base.max_streams_per_agent = 0));
    let outcome = subscribe(Arc::clone(&state), identified(SubscribeRequest::default())).await;
    assert_eq!(outcome.err().map(|status| status.code()), Some(Code::ResourceExhausted));
    Ok(())
}


fn signed_envelope(sequence: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let command = Command {
        key_id: KEY_ID.to_string(),
        key_class: KeyClass::Routine,
        agent_id: "agent-1".to_string(),
        tenant: "acme".to_string(),
        issued_at: NOW,
        expires_at: NOW + LIFETIME,
        sequence,
        nonce: [1; NONCE_LENGTH],
        action: Action::Ping,
    };
    let signer = memory_signer(SigningKey::from_bytes(&[KEY_SEED; SEED_LENGTH]));
    Ok(sign_command(&command, KEY_ID, signer.as_ref())?)
}


fn agent_verifier(dir: &std::path::Path) -> Result<agent_command::model::Verifier, Box<dyn Error>> {
    let file = dir.join("keys.yaml");
    let public = HEXLOWER.encode(&SigningKey::from_bytes(&[KEY_SEED; SEED_LENGTH]).verifying_key().to_bytes());
    fs::write(
        &file,
        format!(
            "keys:\n  - id: {KEY_ID}\n    class: routine\n    public_key: {public}\n    not_before: {}\n    not_after: {}\n",
            NOW - LIFETIME,
            NOW + KEY_LIFETIME
        ),
    )?;
    let log = genesis_log(io::sink());
    let context = ReloadContext {
        actor_id: "agent".to_owned(),
        tenant: "acme".to_owned(),
        module: "agent-channel".to_owned(),
        target: "keys.yaml".to_owned(),
        request_id: "keys".to_owned(),
    };
    let engine = Arc::new(open_keys_engine(file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(open_verifier_with(
        "agent-1",
        "acme",
        engine,
        Sequences::default(),
        Box::new(|_sequences| Ok(())),
    ))
}


#[tokio::test]
async fn the_agent_accepts_a_valid_command_and_refuses_a_forged_and_a_replayed_one() -> TestResult {
    let valid = signed_envelope(1)?;
    let mut forged = signed_envelope(SECOND)?;
    let last = forged.last_mut().ok_or("empty envelope")?;
    *last ^= 1;
    let commands: CommandSource = envelope_source(vec![valid.clone(), valid, forged]);
    let state = make_state(ChannelSettings::default(), recording_sink(new_stored()), commands);
    let session = session(Arc::clone(&state)).await?;
    let dir = tempdir()?;
    let verifier = agent_verifier(dir.path())?;
    let run = bounded(run_commands(session.channel.clone(), &verifier, &|| NOW)).await??;
    assert_eq!(run.accepted.len(), 1);
    assert_eq!(run.accepted.first().map(|command| command.sequence), Some(FIRST));
    let verdicts = run.verdicts;
    let accepted: Vec<bool> = verdicts.iter().map(|verdict| verdict.accepted).collect();
    assert_eq!(accepted, vec![true, false, false]);
    assert!(verdicts.iter().skip(1).all(|verdict| !verdict.reason.is_empty()));
    assert_eq!(verdicts.first().map(|verdict| verdict.digest.len()), Some(DIGEST_LENGTH));
    assert_eq!(
        (counter(&state.counters.commands_accepted), counter(&state.counters.commands_refused)),
        (FIRST, SECOND)
    );
    finish_session(session).await
}


#[tokio::test]
async fn the_command_stream_of_a_dead_channel_reports_the_status() -> TestResult {
    let dir = tempdir()?;
    let verifier = agent_verifier(dir.path())?;
    let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
    let outcome = bounded(run_commands(channel, &verifier, &|| NOW)).await?;
    assert_eq!(status_code(outcome), Some(Code::Unavailable));
    Ok(())
}


#[tokio::test]
async fn a_report_on_a_dead_channel_reports_the_status() -> TestResult {
    let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
    let verdict = CommandVerdict {
        digest: Vec::new(),
        accepted: true,
        reason: String::new(),
    };
    let outcome = bounded(agent_channel::client::report_command(channel, &verdict)).await?;
    assert!(outcome.is_err());
    Ok(())
}


#[test]
fn a_status_keeps_its_code_in_the_channel_error() -> TestResult {
    let error = status_error(tonic::Status::internal("x"));
    assert!(matches!(error, ChannelError::Status(status) if status.code() == Code::Internal));
    Ok(())
}


#[test]
fn the_default_settings_use_the_documented_bounds() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("settings.yaml");
    fs::write(&file, "max_streams_per_agent: 2\n")?;
    let loaded = core_config::load::load_file::<ChannelSettings>(&file)?;
    assert_eq!(loaded.max_streams_per_agent, usize::try_from(SECOND)?);
    assert_eq!(loaded.max_message_bytes, DEFAULT_MAX_MESSAGE_BYTES);
    fs::write(&file, "unknown: 1\n")?;
    assert!(core_config::load::load_file::<ChannelSettings>(&file).is_err());
    Ok(())
}


#[tokio::test]
async fn subscribe_and_report_are_refused_above_the_request_rate() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|base| base.max_requests_per_window = 0));
    let subscribed = subscribe(Arc::clone(&state), identified(SubscribeRequest::default())).await;
    let reported = report(Arc::clone(&state), identified(CommandReport::default())).await;
    assert_eq!(subscribed.err().map(|status| status.code()), Some(Code::ResourceExhausted));
    assert_eq!(reported.err().map(|status| status.code()), Some(Code::ResourceExhausted));
    Ok(())
}


#[tokio::test]
async fn an_event_stream_without_identity_is_refused_and_one_with_identity_is_acknowledged() -> TestResult {
    let _logging = scoped_logging();
    let (state, stored) = recording_state(ChannelSettings::default());
    let refused = open_push(
        Arc::clone(&state),
        Err(Status::unauthenticated("no verified agent identity")),
        stream::iter(vec![Ok(batch(FIRST))]),
    );
    assert_eq!(refused.err().map(|status| status.code()), Some(Code::Unauthenticated));
    let accepted = open_push(Arc::clone(&state), Ok(agent_identity()), stream::iter(vec![Ok(batch(FIRST))]))?;
    let acknowledgements: Vec<Result<u64, Code>> = accepted
        .into_inner()
        .map(|item| item.map(|ack| ack.sequence).map_err(|status| status.code()))
        .collect()
        .await;
    assert_eq!(acknowledgements, vec![Ok(FIRST)]);
    assert_eq!(stored_count(&stored)?, 1);
    Ok(())
}
