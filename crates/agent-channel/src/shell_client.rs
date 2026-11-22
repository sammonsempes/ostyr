use crate::client::{status_error, within_deadline};
use crate::error::ChannelError;
use crate::model::{
    ServerFrame, ShellClientEnd, WireScan, MAX_SHELL_FRAME_BYTES, MAX_SHELL_MESSAGE_BYTES, MAX_TERMINAL_CELLS, SHELL_DEAD_SECONDS,
    SHELL_KEEPALIVE_SECONDS, SHELL_PATH, SHELL_REFUSED_TEXT, SHELL_WRITE_SECONDS,
};
use crate::proto::shell_frame::Frame;
use crate::proto::{ShellClose, ShellCloseReason, ShellFrame, ShellKeepalive, ShellOpen};
use crate::shell_wire::{new_wire_lengths, pop_wire_length, scan_chunk};
use crate::types::{ShellInbound, ShellReader, ShellWriter, WireLengths};
use futures_util::{stream, Stream, StreamExt, TryStreamExt};
use http::uri::PathAndQuery;
use http_body_util::BodyExt;
use prost::Message;
use std::future::ready;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::{interval_at, timeout, Instant};
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::Elapsed;
use tonic::client::Grpc;
use tonic::transport::Channel;
use tonic::{Code, Status};
use tonic_prost::ProstCodec;
use tower::util::ServiceExt;


pub fn frame_of(frame: Frame) -> ShellFrame {
    ShellFrame { frame: Some(frame) }
}


pub fn close_frame(reason: ShellCloseReason) -> ShellFrame {
    frame_of(Frame::Close(ShellClose { reason: i32::from(reason) }))
}


/// The data frames of one read, none above `MAX_SHELL_FRAME_BYTES`.
pub fn data_frames(bytes: &[u8]) -> Vec<ShellFrame> {
    bytes
        .chunks(MAX_SHELL_FRAME_BYTES)
        .map(|chunk| frame_of(Frame::Data(chunk.to_vec())))
        .collect()
}


/// The frames of the agent's shell output; the stream ends after a `Close` with `Exited` (end of output) or `AgentError` (a failed read).
pub fn reader_frames(reader: ShellReader) -> impl Stream<Item = ShellFrame> + Send {
    stream::unfold(Some(reader), |state| async move {
        let mut output = state?;
        match output.next().await {
            Some(Ok(bytes)) => Some((data_frames(&bytes), Some(output))),
            Some(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "shell output failed, closing the session");
                Some((vec![close_frame(ShellCloseReason::AgentError)], None))
            }
            None => Some((vec![close_frame(ShellCloseReason::Exited)], None)),
        }
    })
    .flat_map(stream::iter)
}


/// `Open` first, then the output and a keepalive every `SHELL_KEEPALIVE_SECONDS`; the stream ends once the output has ended.
pub fn outbound_frames(session_id: &str, reader: ShellReader) -> impl Stream<Item = ShellFrame> + Send {
    let period = Duration::from_secs(SHELL_KEEPALIVE_SECONDS);
    let ticks = IntervalStream::new(interval_at(Instant::now() + period, period));
    let keepalives = ticks.map(|_tick| Some(frame_of(Frame::Keepalive(ShellKeepalive {}))));
    let output = reader_frames(reader).map(Some).chain(stream::once(ready(None)));
    let open = frame_of(Frame::Open(ShellOpen {
        session_id: session_id.to_owned(),
    }));
    let running = stream::select(output, keepalives)
        .take_while(|item| ready(item.is_some()))
        .filter_map(ready);
    stream::once(ready(open)).chain(running)
}


/// The frames a server may send: data of 1 to `MAX_SHELL_FRAME_BYTES`, a size of 1 to `MAX_TERMINAL_CELLS` cells each way, a close with a known reason.
pub fn server_frame(frame: ShellFrame) -> Option<ServerFrame> {
    let cells = 1..=MAX_TERMINAL_CELLS;
    match frame.frame {
        Some(Frame::Data(bytes)) if (1..=MAX_SHELL_FRAME_BYTES).contains(&bytes.len()) => Some(ServerFrame::Data(bytes)),
        Some(Frame::Resize(size)) if cells.contains(&size.cols) && cells.contains(&size.rows) => Some(ServerFrame::Resize {
            cols: size.cols,
            rows: size.rows,
        }),
        Some(Frame::Close(close)) if is_known_reason(close.reason) => Some(ServerFrame::Close),
        _ => None,
    }
}


/// A close reason the platform defines, other than the unspecified one.
pub fn is_known_reason(value: i32) -> bool {
    ShellCloseReason::try_from(value).is_ok_and(|reason| reason != ShellCloseReason::Unspecified)
}


/// Records the length each message of the response announces, before tonic decodes it, so a frame carrying unknown fields is seen.
pub fn scan_response(response: http::Response<tonic::body::Body>, lengths: WireLengths) -> http::Response<tonic::body::Body> {
    response.map(|body| {
        let mut scan = WireScan::default();
        tonic::body::Body::new(body.map_frame(move |frame| {
            frame.map_data(|data| {
                scan = scan_chunk(scan, &data, &lengths);
                data
            })
        }))
    })
}


/// Writes the bytes within `SHELL_WRITE_SECONDS`.
pub async fn write_bounded(writer: &mut ShellWriter, bytes: &[u8]) -> Result<(), ShellClientEnd> {
    let written = timeout(Duration::from_secs(SHELL_WRITE_SECONDS), async {
        writer.write_all(bytes).await?;
        writer.flush().await
    })
    .await;
    match written {
        Err(_elapsed) => {
            tracing::warn!(seconds = SHELL_WRITE_SECONDS, "shell writer did not take the input, closed");
            Err(ShellClientEnd::WriteTimeout)
        }
        Ok(Err(error)) => {
            tracing::warn!(kind = ?error.kind(), "shell writer failed, closed");
            Err(ShellClientEnd::WriteFailed)
        }
        Ok(Ok(())) => Ok(()),
    }
}


pub fn transport_end(status: &Status) -> ShellClientEnd {
    if status.code() == Code::OutOfRange {
        ShellClientEnd::Oversized
    } else {
        ShellClientEnd::Transport
    }
}


/// Applies one server frame: data to the writer, a size noted, a close ends; a decoded frame shorter than its wire length carried unknown fields.
pub async fn apply_frame(writer: &mut ShellWriter, frame: ShellFrame, wire: usize) -> Result<(), ShellClientEnd> {
    let exact = frame.encoded_len() == wire;
    let accepted = server_frame(frame).filter(|_| exact).ok_or_else(|| {
        tracing::warn!("shell frame from the server malformed, closed");
        ShellClientEnd::Malformed
    })?;
    match accepted {
        ServerFrame::Data(bytes) => write_bounded(writer, &bytes).await,
        ServerFrame::Resize { cols, rows } => {
            tracing::info!(cols, rows, "shell terminal size received");
            Ok(())
        }
        ServerFrame::Close => Err(ShellClientEnd::ServerClosed),
    }
}


pub async fn step(writer: &mut ShellWriter, item: Result<Result<(ShellFrame, usize), Status>, Elapsed>) -> Result<(), ShellClientEnd> {
    match item {
        Err(_elapsed) => {
            tracing::warn!(seconds = SHELL_DEAD_SECONDS, "shell stream silent, closed");
            Err(ShellClientEnd::Dead)
        }
        Ok(Err(status)) => Err(transport_end(&status)),
        Ok(Ok((frame, wire))) => apply_frame(writer, frame, wire).await,
    }
}


/// Reads the server frames, each wait under `SHELL_DEAD_SECONDS`, until the first end.
pub async fn pump(inbound: ShellInbound, writer: &mut ShellWriter) -> ShellClientEnd {
    let ended = tokio_stream::StreamExt::timeout(inbound, Duration::from_secs(SHELL_DEAD_SECONDS))
        .map(Ok)
        .try_fold(writer, |output, item| async move { step(output, item).await.map(|()| output) })
        .await;
    ended.err().unwrap_or(ShellClientEnd::StreamEnded)
}


/// The refusal of an attach with the code of the server status and a fixed text: the server's message never reaches an error.
pub fn refusal(status: Status) -> ChannelError {
    status_error(Status::new(status.code(), SHELL_REFUSED_TEXT))
}


/// Attaches the shell of an `OpenShell` the agent verified and accepted: `Open` goes first, never on a server frame; ends at the first end of the session.
pub async fn attach_shell(channel: Channel, session_id: &str, reader: ShellReader, mut writer: ShellWriter) -> Result<ShellClientEnd, ChannelError> {
    let lengths = new_wire_lengths();
    let announced = lengths.clone();
    let scanned = channel.map_response(move |response| scan_response(response, announced.clone()));
    let mut grpc = Grpc::new(scanned).max_decoding_message_size(MAX_SHELL_MESSAGE_BYTES);
    let opened = within_deadline(async {
        grpc.ready().await?;
        grpc.streaming(
            tonic::Request::new(outbound_frames(session_id, reader)),
            PathAndQuery::from_static(SHELL_PATH),
            ProstCodec::<ShellFrame, ShellFrame>::default(),
        )
        .await
        .map_err(refusal)
    })
    .await?;
    let inbound = opened.into_inner().map_ok(move |frame| (frame, pop_wire_length(&lengths)));
    Ok(pump(Box::pin(inbound), &mut writer).await)
}
