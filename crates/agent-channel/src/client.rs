use crate::error::ChannelError;
use crate::model::{
    CommandVerdict, CONNECT_TIMEOUT_SECONDS, DEFAULT_MAX_MESSAGE_BYTES, EVENTS_PATH, HEARTBEAT_PATH, PLACEHOLDER_ENDPOINT, REPORT_PATH,
    SUBSCRIBE_PATH,
};
use crate::proto::{BeatReply, BeatRequest, CommandEnvelope, CommandReport, EventAck, EventBatch, ReportReply, SubscribeRequest};
use crate::types::{ClockFn, SharedClientConfig};
use agent_command::model::Verifier;
use agent_command::verify::verify_command;
use futures_util::{stream, Stream, TryStreamExt};
use http::uri::PathAndQuery;
use http::Uri;
use hyper_util::rt::TokioIo;
use ring::digest::{digest, SHA256};
use rustls_pki_types::ServerName;
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


/// Verifies one envelope with `agent_command::verify_command`; the verdict keeps the digest and the refusal reason, never the command.
pub fn judge(verifier: &Verifier, envelope: &[u8], now: u64) -> CommandVerdict {
    let outcome = verify_command(verifier, envelope, now);
    CommandVerdict {
        digest: digest_of(envelope),
        accepted: outcome.is_ok(),
        reason: outcome.err().map_or_else(String::new, |refusal| refusal.to_string()),
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
    mut verdicts: Vec<CommandVerdict>,
) -> Result<Vec<CommandVerdict>, ChannelError> {
    let verdict = judge(verifier, &envelope, clock());
    report_command(channel, &verdict).await?;
    verdicts.push(verdict);
    Ok(verdicts)
}


/// Subscribes, verifies every envelope streamed by the server and reports `accepted` or `refused`; returns the verdicts when the stream ends.
pub async fn run_commands(channel: Channel, verifier: &Verifier, clock: &ClockFn) -> Result<Vec<CommandVerdict>, ChannelError> {
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
        .try_fold(Vec::new(), move |verdicts, received| {
            judge_and_report(channel.clone(), verifier, clock, received.envelope, verdicts)
        })
        .await
}
