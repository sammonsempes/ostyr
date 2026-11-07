use crate::limits::{admit_request, bump, check_claim, count_oversized, open_stream};
use crate::model::{Identity, PushSession, EVENTS_PATH, HEARTBEAT_PATH, REPORT_PATH, SUBSCRIBE_PATH};
use crate::proto::{BeatReply, BeatRequest, CommandEnvelope, CommandReport, EventAck, EventBatch, ReportReply, SubscribeRequest};
use crate::types::{AckStream, BoxError, EnvelopeStream, GrpcResponse, SharedState};
use axum::body::Body;
use axum::Router;
use data_encoding::HEXLOWER;
use futures_util::{Stream, StreamExt};
use http::Request;
use std::convert::Infallible;
use std::sync::Arc;
use tonic::server::Grpc;
use tonic::{Status, Streaming};
use tonic_prost::ProstCodec;
use tower::service_fn;


/// One route per RPC; every route shares `state` (bounds, counters, sink, command source).
pub fn channel_router(state: SharedState) -> Router {
    let events = Arc::clone(&state);
    let subscribe = Arc::clone(&state);
    let report = Arc::clone(&state);
    Router::new()
        .route_service(HEARTBEAT_PATH, service_fn(move |request| heartbeat_route(Arc::clone(&state), request)))
        .route_service(EVENTS_PATH, service_fn(move |request| events_route(Arc::clone(&events), request)))
        .route_service(
            SUBSCRIBE_PATH,
            service_fn(move |request| subscribe_route(Arc::clone(&subscribe), request)),
        )
        .route_service(REPORT_PATH, service_fn(move |request| report_route(Arc::clone(&report), request)))
}


/// Unary failures reach the caller as a response head: this counts the ones refused for size.
pub fn count_oversized_response(state: &SharedState, response: GrpcResponse) -> GrpcResponse {
    if let Some(status) = Status::from_header_map(response.headers()) {
        count_oversized(state, &status);
    }
    response
}


pub async fn heartbeat_route(state: SharedState, request: Request<Body>) -> Result<GrpcResponse, Infallible> {
    let handler_state = Arc::clone(&state);
    let response = Grpc::new(ProstCodec::<BeatReply, BeatRequest>::default())
        .max_decoding_message_size(state.settings.max_message_bytes)
        .unary(service_fn(move |beat_request| beat(Arc::clone(&handler_state), beat_request)), request)
        .await;
    Ok(count_oversized_response(&state, response))
}


pub async fn events_route(state: SharedState, request: Request<Body>) -> Result<GrpcResponse, Infallible> {
    Ok(Grpc::new(ProstCodec::<EventAck, EventBatch>::default())
        .max_decoding_message_size(state.settings.max_message_bytes)
        .streaming(service_fn(move |push_request| push(Arc::clone(&state), push_request)), request)
        .await)
}


pub async fn subscribe_route(state: SharedState, request: Request<Body>) -> Result<GrpcResponse, Infallible> {
    let handler_state = Arc::clone(&state);
    let response = Grpc::new(ProstCodec::<CommandEnvelope, SubscribeRequest>::default())
        .max_decoding_message_size(state.settings.max_message_bytes)
        .server_streaming(
            service_fn(move |subscribe_request| subscribe(Arc::clone(&handler_state), subscribe_request)),
            request,
        )
        .await;
    Ok(count_oversized_response(&state, response))
}


pub async fn report_route(state: SharedState, request: Request<Body>) -> Result<GrpcResponse, Infallible> {
    let handler_state = Arc::clone(&state);
    let response = Grpc::new(ProstCodec::<ReportReply, CommandReport>::default())
        .max_decoding_message_size(state.settings.max_message_bytes)
        .unary(
            service_fn(move |report_request| report(Arc::clone(&handler_state), report_request)),
            request,
        )
        .await;
    Ok(count_oversized_response(&state, response))
}


/// The identity attached by the connection after the handshake; a request without one is refused.
pub fn identity_of<Message>(request: &tonic::Request<Message>) -> Result<Identity, Status> {
    request
        .extensions()
        .get::<Identity>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("no verified agent identity"))
}


/// Answers with the identity taken from the certificate and the heartbeat interval; the request may only repeat that identity.
pub async fn beat(state: SharedState, request: tonic::Request<BeatRequest>) -> Result<tonic::Response<BeatReply>, Status> {
    let identity = identity_of(&request)?;
    admit_request(&state, &identity)?;
    check_claim(&state, &identity, &request.get_ref().tenant, &request.get_ref().agent_id)?;
    Ok(tonic::Response::new(BeatReply {
        tenant: identity.tenant,
        agent_id: identity.agent_id,
        interval_seconds: state.settings.heartbeat_interval_seconds,
    }))
}


/// Opens the acknowledgement stream: one `EventAck` per batch, written only after the sink accepted that batch.
pub async fn push(state: SharedState, request: tonic::Request<Streaming<EventBatch>>) -> Result<tonic::Response<AckStream>, Status> {
    let identity = identity_of(&request);
    open_push(state, identity, request.into_inner())
}


pub fn open_push(
    state: SharedState,
    identity: Result<Identity, Status>,
    inbound: impl Stream<Item = Result<EventBatch, Status>> + Send + 'static,
) -> Result<tonic::Response<AckStream>, Status> {
    let verified = identity?;
    let permit = open_stream(&state, &verified)?;
    let session = Arc::new(PushSession {
        state,
        identity: verified,
        permit,
    });
    let acknowledgements = inbound.then(move |received| acknowledge(Arc::clone(&session), received));
    Ok(tonic::Response::new(Box::pin(acknowledgements)))
}


/// The first refusal or sink failure ends the stream with its status, so no later batch is acknowledged.
pub async fn acknowledge(session: Arc<PushSession>, received: Result<EventBatch, Status>) -> Result<EventAck, Status> {
    let state = &session.state;
    let batch = received.inspect_err(|status| count_oversized(state, status))?;
    admit_request(state, &session.identity)?;
    check_claim(state, &session.identity, &batch.tenant, &batch.agent_id)?;
    let sequence = batch.sequence;
    (state.events)(session.identity.clone(), batch).await.map_err(sink_failure)?;
    bump(&state.counters.events_acknowledged);
    Ok(EventAck { sequence })
}


pub fn sink_failure(error: BoxError) -> Status {
    tracing::warn!(%error, "event sink refused a batch, nothing acknowledged");
    Status::unavailable("event batch not stored")
}


/// Streams the envelope bytes of the injected source; the server never reads them, the agent verifies each one.
pub async fn subscribe(state: SharedState, request: tonic::Request<SubscribeRequest>) -> Result<tonic::Response<EnvelopeStream>, Status> {
    let identity = identity_of(&request)?;
    admit_request(&state, &identity)?;
    check_claim(&state, &identity, &request.get_ref().tenant, &request.get_ref().agent_id)?;
    let permit = open_stream(&state, &identity)?;
    let envelopes = (state.commands)(identity).map(move |envelope| {
        tracing::info!(agent = %permit.identity.agent_id, "command envelope delivered");
        Ok(CommandEnvelope { envelope })
    });
    Ok(tonic::Response::new(Box::pin(envelopes)))
}


/// Records the agent verdict on one envelope: counted and logged with the digest and the reason only.
pub async fn report(state: SharedState, request: tonic::Request<CommandReport>) -> Result<tonic::Response<ReportReply>, Status> {
    let identity = identity_of(&request)?;
    admit_request(&state, &identity)?;
    let verdict = request.get_ref();
    check_claim(&state, &identity, &verdict.tenant, &verdict.agent_id)?;
    let counter = if verdict.accepted {
        &state.counters.commands_accepted
    } else {
        &state.counters.commands_refused
    };
    bump(counter);
    let digest = HEXLOWER.encode(&verdict.envelope_digest);
    tracing::info!(agent = %identity.agent_id, %digest, accepted = verdict.accepted, reason = %verdict.reason, "command verdict reported");
    Ok(tonic::Response::new(ReportReply {}))
}
