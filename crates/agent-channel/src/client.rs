use crate::error::ChannelError;
use crate::limits::bounded_text;
use crate::model::{
    CommandRun, CommandVerdict, Delivered, Delivery, Judged, ATTEMPT_TIMEOUT_SECONDS, BACKOFF_FACTOR, BACKOFF_INITIAL_MILLIS, BACKOFF_MAX_MILLIS,
    CONNECT_TIMEOUT_SECONDS, DEFAULT_MAX_MESSAGE_BYTES, EVENTS_PATH, EXECUTOR_BUSY_REASON, HEARTBEAT_PATH, KEEPALIVE_INTERVAL_SECONDS,
    KEEPALIVE_TIMEOUT_SECONDS, MAX_ACK_READS, MAX_BACKOFF_SHIFT, MAX_IGNORED_ACKS, MAX_KEPT_REFUSALS, MAX_RECONNECT_ATTEMPTS, PLACEHOLDER_ENDPOINT,
    REPORT_PATH, SUBSCRIBE_PATH, UNARY_TIMEOUT_SECONDS,
};
use crate::proto::{BeatReply, BeatRequest, CommandEnvelope, CommandReport, EventAck, EventBatch, ReportReply, SubscribeRequest};
use crate::types::{AckStream, ClockFn, DialFn, ExecuteFn, PauseFn, SharedClientConfig};
use agent_command::model::Verifier;
use agent_command::verify::verify_command;
use futures_util::{stream, Stream, StreamExt, TryStreamExt};
use http::uri::PathAndQuery;
use http::Uri;
use hyper_util::rt::TokioIo;
use ring::digest::{digest, SHA256};
use rustls_pki_types::ServerName;
use std::collections::hash_map::RandomState;
use std::future::Future;
use std::hash::BuildHasher;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at, Instant};
use tokio_rustls::TlsConnector;
use tonic::client::Grpc;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status, Streaming};
use tonic_prost::ProstCodec;
use tower::service_fn;


/// Connects over TLS 1.3, verifying the server certificate against the configured CA and `server_name`.
pub async fn connect_channel(address: SocketAddr, config: SharedClientConfig, server_name: &str) -> Result<Channel, ChannelError> {
    let name = ServerName::try_from(server_name.to_string())?;
    let connector = TlsConnector::from(config);
    let service = service_fn(move |_uri: Uri| {
        let attempt_connector = connector.clone();
        let attempt_name = name.clone();
        async move {
            let tcp = TcpStream::connect(address).await?;
            let tls = attempt_connector.connect(attempt_name, tcp).await?;
            Ok::<_, io::Error>(TokioIo::new(tls))
        }
    });
    let channel = Endpoint::from_static(PLACEHOLDER_ENDPOINT)
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
        .http2_keep_alive_interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS))
        .keep_alive_timeout(Duration::from_secs(KEEPALIVE_TIMEOUT_SECONDS))
        .keep_alive_while_idle(true)
        .connect_with_connector(service)
        .await?;
    Ok(channel)
}


pub fn status_error(status: Status) -> ChannelError {
    ChannelError::Status(Box::new(status))
}


/// A ready client whose decoding bound matches the server one.
pub async fn ready_grpc(channel: Channel) -> Result<Grpc<Channel>, ChannelError> {
    let mut grpc = Grpc::new(channel).max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES);
    grpc.ready().await?;
    Ok(grpc)
}


/// Runs one unary call under `UNARY_TIMEOUT_SECONDS`; a hit is logged and returned as `CallTimedOut`.
pub async fn within_deadline<Output>(call: impl Future<Output = Result<Output, ChannelError>>) -> Result<Output, ChannelError> {
    match timeout(Duration::from_secs(UNARY_TIMEOUT_SECONDS), call).await {
        Ok(outcome) => outcome,
        Err(_elapsed) => {
            tracing::warn!(seconds = UNARY_TIMEOUT_SECONDS, "unary call not answered before the deadline");
            Err(ChannelError::CallTimedOut {
                seconds: UNARY_TIMEOUT_SECONDS,
            })
        }
    }
}


pub async fn heartbeat(channel: Channel, agent_version: &str) -> Result<BeatReply, ChannelError> {
    within_deadline(send_heartbeat(channel, agent_version)).await
}


async fn send_heartbeat(channel: Channel, agent_version: &str) -> Result<BeatReply, ChannelError> {
    let mut grpc = ready_grpc(channel).await?;
    let reply = grpc
        .unary(
            tonic::Request::new(BeatRequest {
                agent_version: agent_version.to_string(),
                ..BeatRequest::default()
            }),
            PathAndQuery::from_static(HEARTBEAT_PATH),
            ProstCodec::<BeatRequest, BeatReply>::default(),
        )
        .await
        .map_err(status_error)?;
    Ok(reply.into_inner())
}


/// Opens the event stream; the server acknowledges each batch only after its sink accepted it.
pub async fn open_event_stream(
    channel: Channel,
    batches: impl Stream<Item = EventBatch> + Send + 'static,
) -> Result<Streaming<EventAck>, ChannelError> {
    let mut grpc = ready_grpc(channel).await?;
    let response = grpc
        .streaming(
            tonic::Request::new(batches),
            PathAndQuery::from_static(EVENTS_PATH),
            ProstCodec::<EventBatch, EventAck>::default(),
        )
        .await
        .map_err(status_error)?;
    Ok(response.into_inner())
}


/// Sends the batches and returns the sequence numbers the server acknowledged; a refusal or a failing sink ends the stream with an error.
pub async fn push_events(channel: Channel, batches: Vec<EventBatch>) -> Result<Vec<u64>, ChannelError> {
    let acknowledgements = open_event_stream(channel, stream::iter(batches)).await?;
    acknowledgements
        .map_ok(|acknowledgement| acknowledgement.sequence)
        .map_err(status_error)
        .try_collect()
        .await
}


pub fn digest_of(envelope: &[u8]) -> Vec<u8> {
    digest(&SHA256, envelope).as_ref().to_vec()
}


/// Verifies one envelope with `agent_command::verify_command`; the verdict keeps the digest and the refusal reason, the accepted command travels beside it.
pub fn judge(verifier: &Verifier, envelope: &[u8], now: u64) -> Judged {
    let outcome = verify_command(verifier, envelope, now);
    let digest = digest_of(envelope);
    match outcome {
        Ok(command) => Judged {
            verdict: CommandVerdict {
                digest,
                accepted: true,
                reason: String::new(),
            },
            command: Some(command),
        },
        Err(refusal) => Judged {
            verdict: CommandVerdict {
                digest,
                accepted: false,
                reason: refusal.to_string(),
            },
            command: None,
        },
    }
}


pub async fn report_command(channel: Channel, verdict: &CommandVerdict) -> Result<(), ChannelError> {
    within_deadline(send_report(channel, verdict)).await
}


async fn send_report(channel: Channel, verdict: &CommandVerdict) -> Result<(), ChannelError> {
    let mut grpc = ready_grpc(channel).await?;
    grpc.unary(
        tonic::Request::new(CommandReport {
            envelope_digest: verdict.digest.clone(),
            accepted: verdict.accepted,
            reason: verdict.reason.clone(),
            ..CommandReport::default()
        }),
        PathAndQuery::from_static(REPORT_PATH),
        ProstCodec::<CommandReport, ReportReply>::default(),
    )
    .await
    .map_err(status_error)?;
    Ok(())
}


/// Counts the verdict; a refusal is kept only while fewer than `MAX_KEPT_REFUSALS` are held, later ones are logged and dropped.
pub fn record_verdict(mut run: CommandRun, verdict: CommandVerdict) -> CommandRun {
    if verdict.accepted {
        run.accepted += 1;
    } else {
        run.refused += 1;
        if run.refusals.len() < MAX_KEPT_REFUSALS {
            run.refusals.push(verdict);
        } else {
            tracing::warn!(reason = ?bounded_text(&verdict.reason), "refusal verdict dropped past the kept cap");
        }
    }
    run
}


pub async fn judge_and_report(
    channel: Channel,
    verifier: &Verifier,
    clock: &ClockFn,
    execute: &ExecuteFn,
    envelope: Vec<u8>,
    run: CommandRun,
) -> Result<CommandRun, ChannelError> {
    let judged = judge(verifier, &envelope, clock());
    let queued = judged.command.is_none_or(execute);
    let verdict = if queued { judged.verdict } else { busy_verdict(judged.verdict.digest) };
    report_command(channel, &verdict).await?;
    Ok(record_verdict(run, verdict))
}


/// The verdict of an accepted command the executor could not take over: refused and reported, never silently lost.
pub fn busy_verdict(digest: Vec<u8>) -> CommandVerdict {
    CommandVerdict {
        digest,
        accepted: false,
        reason: EXECUTOR_BUSY_REASON.to_owned(),
    }
}


/// Executes each accepted command at once, reports every verdict, keeps counts and at most `MAX_KEPT_REFUSALS` refusals.
pub async fn run_commands(channel: Channel, verifier: &Verifier, clock: &ClockFn, execute: &ExecuteFn) -> Result<CommandRun, ChannelError> {
    let mut grpc = ready_grpc(channel.clone()).await?;
    let envelopes = grpc
        .server_streaming(
            tonic::Request::new(SubscribeRequest::default()),
            PathAndQuery::from_static(SUBSCRIBE_PATH),
            ProstCodec::<SubscribeRequest, CommandEnvelope>::default(),
        )
        .await
        .map_err(status_error)?
        .into_inner();
    envelopes
        .map_err(status_error)
        .try_fold(CommandRun::default(), move |run, received| {
            judge_and_report(channel.clone(), verifier, clock, execute, received.envelope, run)
        })
        .await
}


/// Equal jitter: half of the exponential delay plus a share of the other half chosen by `jitter`; never above `BACKOFF_MAX_MILLIS`.
pub fn backoff_delay(attempt: u32, jitter: u64) -> Duration {
    let exponential = BACKOFF_INITIAL_MILLIS.saturating_mul(BACKOFF_FACTOR.saturating_pow(attempt.min(MAX_BACKOFF_SHIFT)));
    let base = exponential.min(BACKOFF_MAX_MILLIS);
    let half = base / BACKOFF_FACTOR;
    Duration::from_millis(half + jitter % (half + 1))
}


/// A process-random value for the jitter: the standard hasher is randomly seeded and no failure is possible.
pub fn random_jitter() -> u64 {
    RandomState::new().hash_one(())
}


/// Reads acknowledgements until every pending batch is settled, the stream ends, `deadline` passes, or `pending.len() + MAX_IGNORED_ACKS` items were read.
pub async fn read_acks(acks: AckStream, pending: &[EventBatch], deadline: Instant) -> (Vec<u64>, Result<(), ChannelError>) {
    let mut limited = acks.take(pending.len() + MAX_IGNORED_ACKS);
    let mut waiting: Vec<u64> = pending.iter().map(|batch| batch.sequence).collect();
    let mut acknowledged = Vec::new();
    let mut read = 0;
    let mut ended = Ok(());
    let mut open = true;
    while open && !waiting.is_empty() && read < MAX_ACK_READS && ended.is_ok() {
        match timeout_at(deadline, limited.next()).await {
            Ok(Some(Ok(ack))) => {
                waiting.retain(|sequence| *sequence != ack.sequence);
                acknowledged.push(ack.sequence);
            }
            Ok(Some(Err(status))) => ended = Err(status_error(status)),
            Ok(None) => open = false,
            Err(_elapsed) => ended = Err(attempt_timed_out()),
        }
        read += 1;
    }
    (acknowledged, ended)
}


pub fn attempt_timed_out() -> ChannelError {
    ChannelError::AttemptTimedOut {
        seconds: ATTEMPT_TIMEOUT_SECONDS,
    }
}


/// Dials, opens the stream with the pending batches and reads the acknowledgements, all within `ATTEMPT_TIMEOUT_SECONDS`.
pub async fn send_pending(dial: &DialFn, pending: &[EventBatch]) -> (Vec<u64>, Result<(), ChannelError>) {
    let deadline = Instant::now() + Duration::from_secs(ATTEMPT_TIMEOUT_SECONDS);
    match timeout_at(deadline, open_pending(dial, pending)).await {
        Ok(Ok(acknowledgements)) => read_acks(Box::pin(acknowledgements), pending, deadline).await,
        Ok(Err(error)) => (Vec::new(), Err(error)),
        Err(_elapsed) => (Vec::new(), Err(attempt_timed_out())),
    }
}


pub async fn open_pending(dial: &DialFn, pending: &[EventBatch]) -> Result<Streaming<EventAck>, ChannelError> {
    let channel = dial().await?;
    open_event_stream(channel, stream::iter(pending.to_vec())).await
}


/// Folds one attempt into the delivery: only the acknowledgement of a pending batch is progress; any other is ignored and logged.
pub fn settle(mut delivery: Delivery, acknowledged: Vec<u64>, ended: Result<(), ChannelError>) -> Delivery {
    let before = delivery.pending.len();
    let confirmed: Vec<u64> = delivery
        .pending
        .iter()
        .map(|batch| batch.sequence)
        .filter(|sequence| acknowledged.contains(sequence))
        .collect();
    delivery.pending.retain(|batch| !confirmed.contains(&batch.sequence));
    if ended.as_ref().err().is_some_and(is_size_refusal) && !delivery.pending.is_empty() {
        let refused = delivery.pending.remove(0);
        tracing::warn!(sequence = refused.sequence, "batch refused by the server as too large, quarantined");
        delivery.rejected.push(refused);
    }
    let progressed = delivery.pending.len() < before;
    let ignored = acknowledged.len() - acknowledged.iter().filter(|sequence| confirmed.contains(sequence)).count();
    if ignored > 0 {
        tracing::warn!(ignored, "acknowledgements for batches not pending were ignored");
    }
    delivery.acknowledged.extend(confirmed);
    delivery.last = match ended {
        Ok(()) if !delivery.pending.is_empty() => Err(ChannelError::StreamEnded {
            unacknowledged: delivery.pending.len(),
        }),
        Err(_) if delivery.pending.is_empty() => Ok(()),
        other => other,
    };
    delivery.failures = if delivery.last.is_err() && !progressed {
        delivery.failures + 1
    } else {
        0
    };
    delivery
}


/// The server refused a message as too large (`OutOfRange`, the codec's size refusal): the first unacknowledged batch is the one.
pub fn is_size_refusal(error: &ChannelError) -> bool {
    matches!(error, ChannelError::Status(status) if status.code() == Code::OutOfRange)
}


pub async fn attempt_delivery(dial: &DialFn, pause: &PauseFn, delivery: Delivery) -> Delivery {
    if delivery.failures > 0 {
        pause(backoff_delay(delivery.failures - 1, random_jitter())).await;
    }
    let (acknowledged, ended) = send_pending(dial, &delivery.pending).await;
    settle(delivery, acknowledged, ended)
}


/// Reconnects after every failure with a bounded jittered backoff, resends exactly the unacknowledged batches, gives up after `MAX_RECONNECT_ATTEMPTS`.
pub async fn deliver_events(dial: &DialFn, pause: &PauseFn, batches: Vec<EventBatch>) -> Result<Delivered, ChannelError> {
    let mut delivery = Delivery {
        pending: batches,
        acknowledged: Vec::new(),
        rejected: Vec::new(),
        failures: 0,
        last: Ok(()),
    };
    while !delivery.pending.is_empty() && delivery.failures < MAX_RECONNECT_ATTEMPTS {
        delivery = attempt_delivery(dial, pause, delivery).await;
    }
    match delivery.last {
        Err(last) => Err(ChannelError::RetriesExhausted {
            attempts: delivery.failures,
            last: Box::new(last),
        }),
        Ok(()) => Ok(Delivered {
            acknowledged: delivery.acknowledged,
            rejected: delivery.rejected,
        }),
    }
}
