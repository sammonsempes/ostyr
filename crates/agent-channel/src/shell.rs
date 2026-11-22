use crate::limits::{admit_request, bounded_text, bump, count_oversized_at, open_slot};
use crate::model::ActiveShell;
use crate::model::{
    AgentCloseReason, AgentFrame, Identity, ShellEnd, ShellIn, ShellInput, ShellMeter, ShellRun, ShellSinkEvent, SlotKind, SlotPermit,
    MAX_SHELL_BYTES_PER_SESSION, MAX_SHELL_FRAMES_PER_SECOND, MAX_SHELL_FRAMES_PER_SESSION, MAX_SHELL_FRAME_BYTES, MAX_SHELL_MESSAGE_BYTES,
    MAX_TERMINAL_CELLS, SHELL_DEAD_SECONDS, SHELL_OPEN_SECONDS, SHELL_OUTBOUND_CAPACITY, SHELL_PATH, SHELL_RATE_WINDOW_SECONDS, SHELL_SEND_SECONDS,
    SHELL_SINK_SECONDS,
};
use crate::proto::shell_frame::Frame;
use crate::proto::{ShellClose, ShellCloseReason, ShellFrame, ShellResize};
use crate::services::{channel_router, guarded, identity_of};
use crate::shell_gate::{gate_has_pending, gate_take};
use crate::shell_wire::{new_wire_lengths, pop_wire_length, scanned_body};
use crate::types::{FirstShellItem, SharedShell, SharedState, ShellInbound, ShellStream, WireLengths};
use agent_command::action::valid_session_id;
use agent_command::model::CLOCK_SKEW_SECONDS;
use axum::body::Body;
use axum::Router;
use futures_util::{stream, Stream, StreamExt, TryStreamExt};
use http::Request;
use prost::Message;
use std::convert::Infallible;
use std::future::ready;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Elapsed;
use tonic::server::Grpc;
use tonic::{Code, Status, Streaming};
use tonic_prost::ProstCodec;
use tower::service_fn;


/// The channel router plus the shell route, which shares the state and the injected gate, sink and source.
pub fn shell_router(state: SharedState, shell: SharedShell) -> Router {
    let route_state = Arc::clone(&state);
    channel_router(state).route_service(
        SHELL_PATH,
        service_fn(move |request| shell_route(Arc::clone(&route_state), Arc::clone(&shell), request)),
    )
}


pub async fn shell_route(state: SharedState, shell: SharedShell, request: Request<Body>) -> Result<crate::types::GrpcResponse, Infallible> {
    let route_state = Arc::clone(&state);
    guarded(&route_state, request, move |admitted| async move {
        let lengths = new_wire_lengths();
        let scanned = admitted.map(|body| scanned_body(body, Arc::clone(&lengths)));
        Ok(Grpc::new(ProstCodec::<ShellFrame, ShellFrame>::default())
            .max_decoding_message_size(MAX_SHELL_MESSAGE_BYTES)
            .streaming(
                service_fn(move |attach_request| attach(Arc::clone(&state), Arc::clone(&shell), Arc::clone(&lengths), attach_request)),
                scanned,
            )
            .await)
    })
    .await
}


pub async fn attach(
    state: SharedState,
    shell: SharedShell,
    lengths: WireLengths,
    request: tonic::Request<Streaming<ShellFrame>>,
) -> Result<tonic::Response<ShellStream>, Status> {
    let identity = identity_of(&request);
    let metered = request.into_inner().map_ok(move |frame| (frame, pop_wire_length(&lengths)));
    open_metered_shell(state, shell, identity, metered).await
}


/// `open_metered_shell` for a stream whose messages are known to carry no unknown field: each wire length is the decoded one.
pub async fn open_shell(
    state: SharedState,
    shell: SharedShell,
    identity: Result<Identity, Status>,
    inbound: impl Stream<Item = Result<ShellFrame, Status>> + Send + 'static,
) -> Result<tonic::Response<ShellStream>, Status> {
    let metered = inbound.map_ok(|frame| {
        let length = frame.encoded_len();
        (frame, length)
    });
    open_metered_shell(state, shell, identity, metered).await
}


/// Checks in order: identity, request rate, a pending session, the shell slot, the `Open` frame, the atomic take; then runs the session.
pub async fn open_metered_shell(
    state: SharedState,
    shell: SharedShell,
    identity: Result<Identity, Status>,
    inbound: impl Stream<Item = Result<(ShellFrame, usize), Status>> + Send + 'static,
) -> Result<tonic::Response<ShellStream>, Status> {
    let verified = identity?;
    admit_request(&state, &verified)?;
    expect_session(&state, &shell, &verified)?;
    let permit = open_slot(&state, &verified, SlotKind::Shell)?;
    let mut frames: ShellInbound = Box::pin(inbound);
    let first = timeout(Duration::from_secs(SHELL_OPEN_SECONDS), frames.next()).await;
    let session_id = open_session_id(&state, first)?;
    let take = take_session(&state, &shell, &verified, &session_id)?;
    let (sender, receiver) = mpsc::channel(SHELL_OUTBOUND_CAPACITY);
    let lifetime = Duration::from_secs(take.max_seconds.saturating_add(CLOCK_SKEW_SECONDS));
    let run = Arc::new(ShellRun {
        started: (state.now)(),
        state,
        shell,
        identity: verified,
        session_id,
        lifetime,
        sender,
    });
    bump(&run.state.counters.shell_opened);
    tracing::info!(tenant = %run.identity.tenant, agent = %run.identity.agent_id, session = %run.session_id, "shell session attached");
    tokio::spawn(run_session(run, frames, permit, take.active));
    Ok(tonic::Response::new(Box::pin(ReceiverStream::new(receiver))))
}


pub fn expect_session(state: &SharedState, shell: &SharedShell, identity: &Identity) -> Result<(), Status> {
    if gate_has_pending(&shell.gate, identity) {
        Ok(())
    } else {
        bump(&state.counters.shell_unexpected);
        tracing::warn!(tenant = %identity.tenant, agent = %identity.agent_id, "shell attach without a pending session refused");
        Err(Status::permission_denied("no shell session expected"))
    }
}


pub fn take_session(state: &SharedState, shell: &SharedShell, identity: &Identity, session_id: &str) -> Result<crate::model::ShellTake, Status> {
    gate_take(&shell.gate, identity, session_id).ok_or_else(|| {
        bump(&state.counters.shell_gate_refused);
        tracing::warn!(tenant = %identity.tenant, agent = %identity.agent_id, "shell session refused by the gate");
        Status::permission_denied("shell session refused")
    })
}


pub fn session_of(frame: ShellFrame) -> Option<String> {
    match frame.frame {
        Some(Frame::Open(open)) if valid_session_id(&open.session_id) => Some(open.session_id),
        _ => None,
    }
}


pub fn malformed_open(state: &SharedState) -> Status {
    bump(&state.counters.shell_malformed);
    tracing::warn!("shell open frame malformed, refused");
    Status::invalid_argument("malformed shell open")
}


pub fn open_session_id(state: &SharedState, first: FirstShellItem) -> Result<String, Status> {
    match first {
        Err(_elapsed) => {
            bump(&state.counters.shell_open_timeouts);
            tracing::warn!(seconds = SHELL_OPEN_SECONDS, "shell open frame not received in time, refused");
            Err(Status::deadline_exceeded("shell open timed out"))
        }
        Ok(Some(Ok((frame, wire)))) => Some(frame)
            .filter(|decoded| decoded.encoded_len() == wire)
            .and_then(session_of)
            .ok_or_else(|| malformed_open(state)),
        Ok(Some(Err(status))) => {
            count_oversized_at(state, &status, MAX_SHELL_MESSAGE_BYTES);
            Err(malformed_open(state))
        }
        Ok(None) => Err(malformed_open(state)),
    }
}


pub fn fresh_meter(now: Instant) -> ShellMeter {
    ShellMeter {
        frames: 0,
        bytes: 0,
        window_started: now,
        window_frames: 0,
    }
}


/// Counts one inbound frame of `length` encoded bytes; the error names the bound that was passed.
pub fn meter_frame(meter: ShellMeter, now: Instant, length: usize) -> Result<ShellMeter, &'static str> {
    let fresh = now.saturating_duration_since(meter.window_started) >= Duration::from_secs(SHELL_RATE_WINDOW_SECONDS);
    let counted = ShellMeter {
        frames: meter.frames.saturating_add(1),
        bytes: meter.bytes.saturating_add(u64::try_from(length).unwrap_or(u64::MAX)),
        window_started: if fresh { now } else { meter.window_started },
        window_frames: if fresh { 1 } else { meter.window_frames.saturating_add(1) },
    };
    if counted.window_frames > MAX_SHELL_FRAMES_PER_SECOND {
        Err("frames per second")
    } else if counted.frames > MAX_SHELL_FRAMES_PER_SESSION {
        Err("frames per session")
    } else if counted.bytes > MAX_SHELL_BYTES_PER_SESSION {
        Err("bytes per session")
    } else {
        Ok(counted)
    }
}


pub fn agent_close_reason(value: i32) -> Option<AgentCloseReason> {
    match ShellCloseReason::try_from(value) {
        Ok(ShellCloseReason::Exited) => Some(AgentCloseReason::Exited),
        Ok(ShellCloseReason::AgentError) => Some(AgentCloseReason::AgentError),
        _ => None,
    }
}


/// The frames an agent may send after `Open`; anything else, an empty or oversized `Data` included, is `None`.
pub fn agent_frame(frame: ShellFrame) -> Option<AgentFrame> {
    match frame.frame {
        Some(Frame::Data(bytes)) if (1..=MAX_SHELL_FRAME_BYTES).contains(&bytes.len()) => Some(AgentFrame::Data(bytes)),
        Some(Frame::Keepalive(_)) => Some(AgentFrame::Keepalive),
        Some(Frame::Close(close)) => agent_close_reason(close.reason).map(AgentFrame::Close),
        _ => None,
    }
}


/// The frame the platform may send to the agent; invalid input is `None`.
pub fn input_frame(input: ShellInput) -> Option<ShellFrame> {
    let cells = 1..=MAX_TERMINAL_CELLS;
    match input {
        ShellInput::Data(bytes) if (1..=MAX_SHELL_FRAME_BYTES).contains(&bytes.len()) => Some(Frame::Data(bytes)),
        ShellInput::Resize { cols, rows } if cells.contains(&cols) && cells.contains(&rows) => Some(Frame::Resize(ShellResize { cols, rows })),
        ShellInput::Close(reason) => Some(Frame::Close(ShellClose { reason: i32::from(reason) })),
        _ => None,
    }
    .map(|frame| ShellFrame { frame: Some(frame) })
}


pub fn silence_or_frame(item: Result<Result<(ShellFrame, usize), Status>, Elapsed>) -> ShellIn {
    match item {
        Err(_elapsed) => ShellIn::Silent,
        Ok(Ok((frame, wire))) => ShellIn::Frame(frame, wire),
        Ok(Err(status)) => ShellIn::Transport(status),
    }
}


/// Merges the agent frames, the platform input and the silence timer; ends at the first end of the session, then tells the sink and the agent.
pub async fn run_session(run: Arc<ShellRun>, inbound: ShellInbound, permit: SlotPermit, active: ActiveShell) {
    let incoming = tokio_stream::StreamExt::timeout(inbound, Duration::from_secs(SHELL_DEAD_SECONDS))
        .map(silence_or_frame)
        .chain(stream::once(ready(ShellIn::Eof)));
    let lifetime = run.lifetime;
    let timer = stream::once(async move {
        tokio::time::sleep(lifetime).await;
        ShellIn::Lifetime
    });
    let outgoing = (run.shell.source)(run.identity.clone(), run.session_id.clone())
        .map(ShellIn::Input)
        .chain(stream::once(ready(ShellIn::Input(ShellInput::Close(ShellCloseReason::UserClose)))));
    let ended = stream::select(stream::select(incoming, outgoing), timer)
        .map(Ok)
        .try_fold(fresh_meter((run.state.now)()), |meter, event| step(Arc::clone(&run), meter, event))
        .await;
    finish(&run, ended.err().unwrap_or(ShellEnd::Dropped)).await;
    drop(permit);
    drop(active);
}


pub async fn step(run: Arc<ShellRun>, meter: ShellMeter, event: ShellIn) -> Result<ShellMeter, ShellEnd> {
    let now = (run.state.now)();
    if now.saturating_duration_since(run.started) >= run.lifetime {
        Err(lifetime_end(run.as_ref()))
    } else {
        handle(&run, meter, now, event).await
    }
}


pub fn lifetime_end(run: &ShellRun) -> ShellEnd {
    bump(&run.state.counters.shell_lifetime);
    tracing::warn!("shell session past its lifetime, closed");
    ShellEnd::Lifetime
}


pub async fn handle(run: &ShellRun, meter: ShellMeter, now: Instant, event: ShellIn) -> Result<ShellMeter, ShellEnd> {
    match event {
        ShellIn::Eof => Err(ShellEnd::Dropped),
        ShellIn::Silent => {
            bump(&run.state.counters.shell_dead);
            tracing::warn!(seconds = SHELL_DEAD_SECONDS, "shell stream silent, closed");
            Err(ShellEnd::Dead)
        }
        ShellIn::Lifetime => Err(lifetime_end(run)),
        ShellIn::Transport(status) => {
            count_oversized_at(&run.state, &status, MAX_SHELL_MESSAGE_BYTES);
            Err(transport_end(&status))
        }
        ShellIn::Input(input) => forward(run, input).await.map(|()| meter),
        ShellIn::Frame(frame, wire) => accept_frame(run, meter, now, frame, wire).await,
    }
}


pub fn transport_end(status: &Status) -> ShellEnd {
    if status.code() == Code::OutOfRange {
        ShellEnd::Oversized
    } else {
        ShellEnd::Transport
    }
}


/// Meters the wire length of the message; a decoded frame whose length differs carried unknown fields and is refused.
pub async fn accept_frame(run: &ShellRun, meter: ShellMeter, now: Instant, frame: ShellFrame, wire: usize) -> Result<ShellMeter, ShellEnd> {
    let exact = frame.encoded_len() == wire;
    let agent = agent_frame(frame).filter(|_| exact).ok_or_else(|| {
        bump(&run.state.counters.shell_malformed);
        tracing::warn!("shell frame malformed, closed");
        ShellEnd::Malformed
    })?;
    let counted = meter_frame(meter, now, wire).map_err(|bound| {
        bump(&run.state.counters.shell_budget);
        tracing::warn!(bound, "shell session budget exceeded, closed");
        ShellEnd::Budget
    })?;
    match agent {
        AgentFrame::Data(bytes) => call_sink(run, ShellSinkEvent::Output(bytes)).await.map(|()| counted),
        AgentFrame::Keepalive => call_sink(run, ShellSinkEvent::Tick).await.map(|()| counted),
        AgentFrame::Close(reason) => Err(ShellEnd::AgentClosed(reason)),
    }
}


pub async fn forward(run: &ShellRun, input: ShellInput) -> Result<(), ShellEnd> {
    let closing = matches!(input, ShellInput::Close(_));
    let frame = input_frame(input).ok_or_else(|| {
        bump(&run.state.counters.shell_malformed);
        tracing::warn!("shell input refused, closed");
        ShellEnd::Malformed
    })?;
    send_item(run, Ok(frame)).await?;
    if closing {
        Err(ShellEnd::PlatformClosed)
    } else {
        Ok(())
    }
}


pub async fn send_item(run: &ShellRun, item: Result<ShellFrame, Status>) -> Result<(), ShellEnd> {
    match timeout(Duration::from_secs(SHELL_SEND_SECONDS), run.sender.send(item)).await {
        Err(_elapsed) => {
            bump(&run.state.counters.shell_send_timeouts);
            tracing::warn!(seconds = SHELL_SEND_SECONDS, "agent does not read its shell stream, closed");
            Err(ShellEnd::SendTimeout)
        }
        Ok(Err(_closed)) => Err(ShellEnd::Dropped),
        Ok(Ok(())) => Ok(()),
    }
}


pub async fn call_sink(run: &ShellRun, event: ShellSinkEvent) -> Result<(), ShellEnd> {
    let call = (run.shell.sink)(run.identity.clone(), run.session_id.clone(), event);
    match timeout(Duration::from_secs(SHELL_SINK_SECONDS), call).await {
        Err(_elapsed) => {
            bump(&run.state.counters.shell_sink_timeouts);
            tracing::warn!(seconds = SHELL_SINK_SECONDS, "shell sink did not answer, closed");
            Err(ShellEnd::SinkTimeout)
        }
        Ok(Err(error)) => {
            bump(&run.state.counters.shell_sink_failed);
            let reason = bounded_text(&error.to_string());
            tracing::warn!(?reason, "shell sink refused an event, closed");
            Err(ShellEnd::SinkFailed)
        }
        Ok(Ok(())) => Ok(()),
    }
}


/// The fixed status that ends the stream toward the agent; none when the end is clean or nobody listens.
pub fn end_status(end: ShellEnd) -> Option<Status> {
    match end {
        ShellEnd::AgentClosed(_) | ShellEnd::PlatformClosed | ShellEnd::Dropped | ShellEnd::SendTimeout | ShellEnd::Transport => None,
        ShellEnd::Oversized => Some(Status::out_of_range("shell frame too large")),
        ShellEnd::Dead => Some(Status::deadline_exceeded("shell stream silent")),
        ShellEnd::Lifetime => Some(Status::deadline_exceeded("shell session time limit")),
        ShellEnd::Budget => Some(Status::resource_exhausted("shell session budget exceeded")),
        ShellEnd::Malformed => Some(Status::invalid_argument("malformed shell frame")),
        ShellEnd::SinkTimeout | ShellEnd::SinkFailed => Some(Status::unavailable("shell sink unavailable")),
    }
}


pub async fn finish(run: &ShellRun, end: ShellEnd) {
    tracing::info!(session = %run.session_id, ?end, "shell session ended");
    if !matches!(end, ShellEnd::SinkTimeout | ShellEnd::SinkFailed) {
        if let Err(failed) = call_sink(run, ShellSinkEvent::Ended(end)).await {
            tracing::warn!(?failed, "shell sink not told of the end");
        }
    }
    if let Some(status) = end_status(end) {
        if let Err(failed) = send_item(run, Err(status)).await {
            tracing::warn!(?failed, "shell end status not delivered");
        }
    }
}
