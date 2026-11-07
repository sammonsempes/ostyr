use crate::harness::{attempt_with, bounded, scoped_logging};
use crate::services::{agent_identity, counter, finish_session, recording_state, session, settings, status_code};
use crate::types::TestResult;
use agent_channel::client::{heartbeat, ready_grpc, status_error};
use agent_channel::error::ChannelError;
use agent_channel::limits::{bounded_text, check_claim, lock_load};
use agent_channel::model::{EVENTS_PATH, HEARTBEAT_PATH, MAX_LOGGED_TEXT_CHARS, TRUNCATION_MARKER};
use agent_channel::proto::{BeatReply, BeatRequest, CommandReport};
use agent_channel::services::{heartbeat_route, open_push, report};
use agent_channel::types::SharedState;
use axum::body::Body;
use futures_util::stream;
use http::uri::PathAndQuery;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tonic::transport::Channel;
use tonic::{Code, Request, Status};
use tonic_prost::ProstCodec;


const POLL_ATTEMPTS: u32 = 200;


const POLL_MILLIS: u64 = 25;


const QUIET_MILLIS: u64 = 500;


const EXTRA_ATTEMPTS: u64 = 5;


const LONG_TEXT_CHARS: usize = 10_000;


const LOG_BOUND_BYTES: usize = 4_096;


const LOG_LINES: usize = 3;


#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn stall_heartbeat(channel: Channel) -> JoinHandle<Result<BeatReply, ChannelError>> {
    tokio::spawn(async move {
        let mut grpc = ready_grpc(channel).await?;
        let reply = grpc
            .client_streaming(
                Request::new(stream::pending::<BeatRequest>()),
                PathAndQuery::from_static(HEARTBEAT_PATH),
                ProstCodec::<BeatRequest, BeatReply>::default(),
            )
            .await
            .map_err(status_error)?;
        Ok(reply.into_inner())
    })
}


fn inflight(state: &SharedState) -> usize {
    lock_load(state).get(&agent_identity()).map_or(0, |load| load.inflight)
}


async fn wait_for_inflight(state: &SharedState, expected: usize) -> TestResult {
    let mut attempts = 0;
    while inflight(state) != expected && attempts < POLL_ATTEMPTS {
        sleep(Duration::from_millis(POLL_MILLIS)).await;
        attempts += 1;
    }
    assert_eq!(inflight(state), expected);
    Ok(())
}


#[tokio::test]
async fn requests_above_the_in_flight_bound_are_refused_before_any_body_is_read() -> TestResult {
    let (state, _stored) = recording_state(settings(|base| base.max_inflight_per_agent = 1));
    let session = session(Arc::clone(&state)).await?;
    let stalled = stall_heartbeat(session.channel.clone());
    wait_for_inflight(&state, 1).await?;
    let refusals = futures_util::future::join_all((0..EXTRA_ATTEMPTS).map(|_attempt| heartbeat(session.channel.clone(), "test")));
    let outcomes = bounded(refusals).await?;
    assert!(outcomes.into_iter().all(|outcome| status_code(outcome) == Some(Code::ResourceExhausted)));
    assert_eq!(counter(&state.counters.inflight_limited), EXTRA_ATTEMPTS);
    assert_eq!(inflight(&state), 1);
    stalled.abort();
    finish_session(session).await
}


#[tokio::test]
async fn a_stalled_request_is_cut_at_the_timeout_and_gives_its_slot_back() -> TestResult {
    let (state, _stored) = recording_state(settings(|base| base.request_timeout_seconds = 1));
    let session = session(Arc::clone(&state)).await?;
    let outcome = bounded(stall_heartbeat(session.channel.clone())).await??;
    assert_eq!(status_code(outcome), Some(Code::DeadlineExceeded));
    assert_eq!(counter(&state.counters.timed_out), 1);
    wait_for_inflight(&state, 0).await?;
    finish_session(session).await
}


#[tokio::test]
async fn a_connection_above_the_per_agent_bound_is_refused_and_counted() -> TestResult {
    let (state, _stored) = recording_state(settings(|base| base.max_connections_per_agent = 1));
    let session = session(Arc::clone(&state)).await?;
    let second = bounded(attempt_with(session.server.address, Arc::clone(&session.config))).await?;
    assert!(second.is_err());
    assert_eq!(counter(&state.counters.connection_limited), 1);
    assert!(bounded(heartbeat(session.channel.clone(), "test")).await?.is_ok());
    finish_session(session).await
}


#[tokio::test]
async fn http2_streams_per_connection_are_bounded() -> TestResult {
    let (state, _stored) = recording_state(settings(|base| base.max_streams_per_connection = 1));
    let session = session(Arc::clone(&state)).await?;
    let stalled = stall_heartbeat(session.channel.clone());
    wait_for_inflight(&state, 1).await?;
    let waiting = timeout(Duration::from_millis(QUIET_MILLIS), heartbeat(session.channel.clone(), "test")).await;
    assert!(waiting.is_err());
    assert_eq!(inflight(&state), 1);
    assert_eq!(counter(&state.counters.inflight_limited), 0);
    stalled.abort();
    finish_session(session).await
}


#[test]
fn opening_an_event_stream_counts_as_a_request() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|base| base.max_requests_per_window = 0));
    let opened = open_push(Arc::clone(&state), Ok(agent_identity()), stream::iter(Vec::new()));
    assert_eq!(opened.err().map(|status| status.code()), Some(Code::ResourceExhausted));
    assert_eq!(counter(&state.counters.rate_limited), 1);
    Ok(())
}


#[tokio::test]
async fn a_request_without_identity_is_refused_before_decoding() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|_base| ()));
    let response = heartbeat_route(Arc::clone(&state), http::Request::new(Body::empty())).await?;
    assert_eq!(
        Status::from_header_map(response.headers()).map(|status| status.code()),
        Some(Code::Unauthenticated)
    );
    let event_path = http::Request::builder().uri(EVENTS_PATH).body(Body::empty())?;
    let events = agent_channel::services::events_route(state, event_path).await?;
    assert_eq!(
        Status::from_header_map(events.headers()).map(|status| status.code()),
        Some(Code::Unauthenticated)
    );
    Ok(())
}


#[test]
fn agent_text_is_cut_to_the_logging_bound() -> TestResult {
    assert_eq!(bounded_text("short"), "short");
    let cut = bounded_text(&"x".repeat(LONG_TEXT_CHARS));
    assert_eq!(cut.len(), MAX_LOGGED_TEXT_CHARS + TRUNCATION_MARKER.len());
    assert!(cut.ends_with(TRUNCATION_MARKER));
    Ok(())
}


#[tokio::test]
async fn agent_text_in_the_log_is_escaped_and_bounded() -> TestResult {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt().with_writer(move || writer.clone()).with_ansi(false).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let (state, _stored) = recording_state(settings(|_base| ()));
    let mut forging = Request::new(CommandReport {
        reason: "first\nforged line level=ERROR".to_string(),
        ..CommandReport::default()
    });
    forging.extensions_mut().insert(agent_identity());
    report(Arc::clone(&state), forging).await?;
    let mut flooding = Request::new(CommandReport {
        reason: "y".repeat(LONG_TEXT_CHARS),
        envelope_digest: vec![0; LONG_TEXT_CHARS],
        ..CommandReport::default()
    });
    flooding.extensions_mut().insert(agent_identity());
    report(Arc::clone(&state), flooding).await?;
    let refused = check_claim(&state, &agent_identity(), &format!("a\nb{}", "t".repeat(LONG_TEXT_CHARS)), "agent-1");
    assert!(refused.is_err());
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert_eq!(log.lines().count(), LOG_LINES);
    assert!(log.contains("first\\nforged line"));
    assert!(log.contains(TRUNCATION_MARKER));
    assert!(log.len() < LOG_BOUND_BYTES);
    Ok(())
}
