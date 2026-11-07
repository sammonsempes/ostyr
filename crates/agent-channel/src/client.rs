use crate::error::ChannelError;
use crate::model::{
    CommandRun, CommandVerdict, Delivery, Judged, BACKOFF_FACTOR, BACKOFF_INITIAL_MILLIS, BACKOFF_MAX_MILLIS, CONNECT_TIMEOUT_SECONDS,
    DEFAULT_MAX_MESSAGE_BYTES, EVENTS_PATH, HEARTBEAT_PATH, MAX_BACKOFF_SHIFT, MAX_RECONNECT_ATTEMPTS, PLACEHOLDER_ENDPOINT, REPORT_PATH,
    SUBSCRIBE_PATH,
};
use crate::proto::{BeatReply, BeatRequest, CommandEnvelope, CommandReport, EventAck, EventBatch, ReportReply, SubscribeRequest};
use crate::types::{ClockFn, DialFn, PauseFn, SharedClientConfig};
use agent_command::model::Verifier;
use agent_command::verify::verify_command;
use futures_util::{stream, Stream, StreamExt, TryStreamExt};
use http::uri::PathAndQuery;
use http::Uri;
use hyper_util::rt::TokioIo;
use ring::digest::{digest, SHA256};
use rustls_pki_types::ServerName;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::client::Grpc;
use tonic::transport::{Channel, Endpoint};
use tonic::{Status, Streaming};
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


pub async fn heartbeat(channel: Channel, agent_version: &str) -> Result<BeatReply, ChannelError> {
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


pub async fn judge_and_report(
    channel: Channel,
    verifier: &Verifier,
    clock: &ClockFn,
    envelope: Vec<u8>,
    mut run: CommandRun,
) -> Result<CommandRun, ChannelError> {
    let judged = judge(verifier, &envelope, clock());
    report_command(channel, &judged.verdict).await?;
    run.verdicts.push(judged.verdict);
    run.accepted.extend(judged.command);
    Ok(run)
}


/// Subscribes, verifies every envelope streamed by the server and reports `accepted` or `refused`; returns the verdicts and the accepted commands when the stream ends.
pub async fn run_commands(channel: Channel, verifier: &Verifier, clock: &ClockFn) -> Result<CommandRun, ChannelError> {
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
            judge_and_report(channel.clone(), verifier, clock, received.envelope, run)
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


/// Opens the stream with the pending batches; returns the sequences acknowledged before the stream ended, and how it ended.
pub async fn send_pending(dial: &DialFn, pending: &[EventBatch]) -> (Vec<u64>, Result<(), ChannelError>) {
    match open_pending(dial, pending).await {
        Ok(acknowledgements) => {
            let items: Vec<Result<EventAck, Status>> = acknowledgements.collect().await;
            let acknowledged = items.iter().filter_map(|item| item.as_ref().ok()).map(|ack| ack.sequence).collect();
            let ended = items.into_iter().find_map(Result::err).map_or(Ok(()), |status| Err(status_error(status)));
            (acknowledged, ended)
        }
        Err(error) => (Vec::new(), Err(error)),
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


pub async fn attempt_delivery(dial: &DialFn, pause: &PauseFn, delivery: Delivery) -> Delivery {
    if delivery.failures > 0 {
        pause(backoff_delay(delivery.failures - 1, random_jitter())).await;
    }
    let (acknowledged, ended) = send_pending(dial, &delivery.pending).await;
    settle(delivery, acknowledged, ended)
}


/// Reconnects after every failure with a bounded jittered backoff, resends exactly the unacknowledged batches, gives up after `MAX_RECONNECT_ATTEMPTS`.
pub async fn deliver_events(dial: &DialFn, pause: &PauseFn, batches: Vec<EventBatch>) -> Result<Vec<u64>, ChannelError> {
    let mut delivery = Delivery {
        pending: batches,
        acknowledged: Vec::new(),
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
        Ok(()) => Ok(delivery.acknowledged),
    }
}
