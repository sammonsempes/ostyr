use crate::harness::{
    bounded, client_paths, empty_revocation, make_platform, server_paths, start_server_routed, stop_server, Platform, RunningServer,
};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::services::{agent_identity, counter};
use crate::shell_rig::{approve, close_frame, data_frame, empty_frame, keepalive_frame, next_event, open_frame, resize_frame, rig, Rig, SESSION};
use crate::types::TestResult;
use agent_channel::client::connect_channel;
use agent_channel::error::ChannelError;
use agent_channel::model::{
    ShellClientEnd, ShellEnd, ShellInput, ShellSinkEvent, MAX_SHELL_FRAME_BYTES, SHELL_DEAD_SECONDS, SHELL_KEEPALIVE_SECONDS, SHELL_PATH,
    SHELL_REFUSED_TEXT, SHELL_WRITE_SECONDS,
};
use agent_channel::proto::shell_frame::Frame;
use agent_channel::proto::{ShellClose, ShellCloseReason, ShellFrame, ShellOpen};
use agent_channel::shell::shell_router;
use agent_channel::shell_client::{attach_shell, close_frame as client_close, data_frames, is_known_reason, outbound_frames, pump, server_frame};
use agent_channel::tls::client_config;
use agent_channel::types::{ShellInbound, ShellReader, ShellWriter};
use axum::body::Body;
use axum::Router;
use futures_util::{stream, StreamExt};
use http::Request;
use std::convert::Infallible;
use std::error::Error;
use std::future::ready;
use std::io;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::io::{duplex, AsyncReadExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::server::Grpc;
use tonic::{Code, Status, Streaming};
use tonic_prost::ProstCodec;
use tower::service_fn;


const STALLED_PERIODS: u64 = 5;


const OVERSIZED_PADDING: usize = 1_048_576;


const READ_ALL_BYTES: usize = 204_800;


const LAST_CHUNK_BYTES: usize = 8_192;


const FULL_CHUNKS: usize = 3;


const WRITER_ROOM: usize = 1_048_576;


const TINY_ROOM: usize = 1;


const FEED_DEPTH: usize = 4;


const ECHO_BYTES: usize = 2;


const ZERO_BYTE: u8 = 0;


const ONE_BYTES: usize = 3;


const UNKNOWN_REASON: i32 = 99;


const TWO_PERIODS: u64 = 2;


const FILL_BYTE: u8 = 7;


const OPEN_AND_CLOSE: usize = 2;


const MARKER: &str = "SECRET-MARKER-4471";


const TERMINAL_COLUMNS: u32 = 80;


const TERMINAL_ROWS: u32 = 24;


const TOO_MANY_CELLS: u32 = 1_001;


#[derive(Clone, PartialEq, prost::Message)]
pub struct Mixed {
    #[prost(message, optional, tag = "1")]
    pub open: Option<ShellOpen>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub data: Option<Vec<u8>>,
    #[prost(message, optional, tag = "5")]
    pub close: Option<ShellClose>,
    #[prost(bytes = "vec", tag = "99")]
    pub padding: Vec<u8>,
}


pub struct Wire {
    pub server: RunningServer,
    pub channel: tonic::transport::Channel,
    pub _dir: TempDir,
}


async fn wire_to(router: Router, rig: &Rig) -> Result<Wire, Box<dyn Error>> {
    let dir = tempdir()?;
    let platform: Platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let server = start_server_routed(
        &paths,
        empty_revocation(&paths)?,
        Arc::clone(&rig.state),
        TcpListener::bind("127.0.0.1:0").await?,
        router,
    )
    .await?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let channel = bounded(connect_channel(server.address, client_config(&agent)?, SERVER_NAME)).await??;
    Ok(Wire { server, channel, _dir: dir })
}


fn hostile_router<Message>(script: Vec<Message>) -> Router
where
    Message: prost::Message + Clone + Sync + Send + 'static,
{
    Router::new().route_service(
        SHELL_PATH,
        service_fn(move |request: Request<Body>| {
            let items = script.clone();
            async move {
                Ok::<_, Infallible>(
                    Grpc::new(ProstCodec::<Message, ShellFrame>::default())
                        .streaming(
                            service_fn(move |_attach: tonic::Request<Streaming<ShellFrame>>| {
                                let replies = items.clone();
                                ready(Ok::<_, Status>(tonic::Response::new(stream::iter(replies).map(Ok::<Message, Status>))))
                            }),
                            request,
                        )
                        .await,
                )
            }
        }),
    )
}


fn refusing_router() -> Router {
    Router::new().route_service(
        SHELL_PATH,
        service_fn(move |request: Request<Body>| async move {
            Ok::<_, Infallible>(
                Grpc::new(ProstCodec::<ShellFrame, ShellFrame>::default())
                    .streaming(
                        service_fn(move |_attach: tonic::Request<Streaming<ShellFrame>>| {
                            ready(Err::<tonic::Response<stream::Empty<Result<ShellFrame, Status>>>, Status>(
                                Status::permission_denied(MARKER),
                            ))
                        }),
                        request,
                    )
                    .await,
            )
        }),
    )
}


fn silent_reader() -> ShellReader {
    Box::pin(stream::pending())
}


async fn run_attached(wire: &Wire, reader: ShellReader) -> Result<(ShellClientEnd, Vec<u8>), Box<dyn Error>> {
    let (writer, mut peer) = duplex(WRITER_ROOM);
    let ended = bounded(attach_shell(wire.channel.clone(), SESSION, reader, Box::new(writer))).await??;
    let mut written = Vec::new();
    peer.read_to_end(&mut written).await?;
    Ok((ended, written))
}


async fn against_hostile<Message>(script: Vec<Message>) -> Result<(ShellClientEnd, Vec<u8>), Box<dyn Error>>
where
    Message: prost::Message + Clone + Sync + Send + 'static,
{
    let rig = rig();
    let wire = wire_to(hostile_router(script), &rig).await?;
    let outcome = run_attached(&wire, silent_reader()).await?;
    stop_server(wire.server).await?;
    Ok(outcome)
}


fn mixed_data(bytes: &[u8], padding: usize) -> Mixed {
    Mixed {
        open: None,
        data: Some(bytes.to_vec()),
        close: None,
        padding: vec![0; padding],
    }
}


async fn malformed_from_server(bad: ShellFrame) -> TestResult {
    let (ended, written) = against_hostile(vec![bad, data_frame(b"after")]).await?;
    assert_eq!(ended, ShellClientEnd::Malformed);
    assert!(written.is_empty());
    Ok(())
}


#[tokio::test]
async fn an_attach_echoes_both_ways_against_the_server() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let wire = wire_to(shell_router(Arc::clone(&rig.state), Arc::clone(&rig.shell)), &rig).await?;
    let (writer, mut peer) = duplex(WRITER_ROOM);
    let (feed, output) = mpsc::channel::<io::Result<Vec<u8>>>(FEED_DEPTH);
    let attached = tokio::spawn(attach_shell(
        wire.channel.clone(),
        SESSION,
        Box::pin(ReceiverStream::new(output)),
        Box::new(writer),
    ));
    feed.send(Ok(b"out".to_vec())).await?;
    assert_eq!(next_event(&mut rig).await?, ShellSinkEvent::Output(b"out".to_vec()));
    rig.input
        .send(ShellInput::Resize {
            cols: TERMINAL_COLUMNS,
            rows: TERMINAL_ROWS,
        })
        .await?;
    rig.input.send(ShellInput::Data(b"in".to_vec())).await?;
    let mut echoed = vec![ZERO_BYTE; ECHO_BYTES];
    bounded(peer.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, b"in");
    rig.input.send(ShellInput::Close(ShellCloseReason::UserClose)).await?;
    assert_eq!(
        bounded(attached).await??.map_err(|error| error.to_string())?,
        ShellClientEnd::ServerClosed
    );
    assert_eq!(counter(&rig.state.counters.shell_opened), 1);
    stop_server(wire.server).await?;
    Ok(())
}


#[tokio::test]
async fn the_end_of_the_output_closes_the_session_as_exited() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let wire = wire_to(shell_router(Arc::clone(&rig.state), Arc::clone(&rig.shell)), &rig).await?;
    let output: ShellReader = Box::pin(stream::iter(vec![Ok(b"bye".to_vec())]));
    let (ended, written) = run_attached(&wire, output).await?;
    assert_eq!(ended, ShellClientEnd::StreamEnded);
    assert!(written.is_empty());
    assert_eq!(
        crate::shell_rig::until_ended(&mut rig).await?,
        vec![
            ShellSinkEvent::Output(b"bye".to_vec()),
            ShellSinkEvent::Ended(ShellEnd::AgentClosed(agent_channel::model::AgentCloseReason::Exited))
        ]
    );
    stop_server(wire.server).await?;
    Ok(())
}


#[tokio::test]
async fn an_attach_the_server_refuses_fails_with_a_fixed_error() -> TestResult {
    let rig = rig();
    let wire = wire_to(shell_router(Arc::clone(&rig.state), Arc::clone(&rig.shell)), &rig).await?;
    let refused = bounded(attach_shell(wire.channel.clone(), SESSION, silent_reader(), Box::new(duplex(1).0))).await?;
    assert!(matches!(refused, Err(ChannelError::Status(ref status)) if status.code() == Code::PermissionDenied));
    assert_eq!(counter(&rig.state.counters.shell_unexpected), 1);
    assert_eq!(agent_identity().agent_id, "agent-1");
    stop_server(wire.server).await?;
    Ok(())
}


#[tokio::test]
async fn a_refusal_text_from_the_server_reaches_no_error() -> TestResult {
    let rig = rig();
    let wire = wire_to(refusing_router(), &rig).await?;
    let refused = bounded(attach_shell(wire.channel.clone(), SESSION, silent_reader(), Box::new(duplex(1).0))).await?;
    let error = refused.err().ok_or("attached")?;
    let chain = std::iter::successors(Some(&error as &(dyn Error + 'static)), |inner| (*inner).source());
    let shown = chain.map(|inner| format!("{inner} {inner:?}")).collect::<Vec<_>>().join(" ");
    assert!(!shown.contains(MARKER));
    assert!(shown.contains(SHELL_REFUSED_TEXT));
    stop_server(wire.server).await?;
    Ok(())
}


#[tokio::test]
async fn the_server_input_reaches_the_writer_until_a_close() -> TestResult {
    let (ended, written) = against_hostile(vec![
        data_frame(b"one"),
        resize_frame(TERMINAL_COLUMNS, TERMINAL_ROWS),
        data_frame(&vec![1; MAX_SHELL_FRAME_BYTES]),
        close_frame(i32::from(ShellCloseReason::UserClose)),
        data_frame(b"after"),
    ])
    .await?;
    assert_eq!(ended, ShellClientEnd::ServerClosed);
    assert_eq!(written.len(), MAX_SHELL_FRAME_BYTES + ONE_BYTES);
    assert_eq!(written.get(..ONE_BYTES), Some(b"one".as_slice()));
    Ok(())
}


#[tokio::test]
async fn a_stream_that_ends_without_a_close_ends_the_attach() -> TestResult {
    let (ended, written) = against_hostile(vec![data_frame(b"one")]).await?;
    assert_eq!(ended, ShellClientEnd::StreamEnded);
    assert_eq!(written, b"one");
    Ok(())
}


#[tokio::test]
async fn a_server_open_ends_the_stream() -> TestResult {
    malformed_from_server(open_frame(SESSION)).await
}


#[tokio::test]
async fn a_server_keepalive_ends_the_stream() -> TestResult {
    malformed_from_server(keepalive_frame()).await
}


#[tokio::test]
async fn a_frame_with_no_member_ends_the_stream() -> TestResult {
    malformed_from_server(empty_frame()).await
}


#[tokio::test]
async fn an_unknown_close_reason_ends_the_stream() -> TestResult {
    malformed_from_server(close_frame(UNKNOWN_REASON)).await
}


#[tokio::test]
async fn an_unspecified_close_reason_ends_the_stream() -> TestResult {
    malformed_from_server(close_frame(0)).await
}


#[tokio::test]
async fn an_empty_data_frame_ends_the_stream() -> TestResult {
    malformed_from_server(data_frame(b"")).await
}


#[tokio::test]
async fn a_resize_of_zero_or_too_many_cells_ends_the_stream() -> TestResult {
    malformed_from_server(resize_frame(0, TERMINAL_ROWS)).await?;
    malformed_from_server(resize_frame(TERMINAL_COLUMNS, TOO_MANY_CELLS)).await
}


#[tokio::test]
async fn a_data_frame_with_an_unknown_field_ends_the_stream() -> TestResult {
    let (ended, written) = against_hostile(vec![mixed_data(b"one", 1)]).await?;
    assert_eq!(ended, ShellClientEnd::Malformed);
    assert!(written.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_frame_over_the_shell_bound_is_refused_by_the_codec() -> TestResult {
    let (ended, written) = against_hostile(vec![mixed_data(b"one", OVERSIZED_PADDING)]).await?;
    assert_eq!(ended, ShellClientEnd::Oversized);
    assert!(written.is_empty());
    let (just_over, nothing) = against_hostile(vec![data_frame(&vec![1; MAX_SHELL_FRAME_BYTES + 1])]).await?;
    assert_eq!(just_over, ShellClientEnd::Oversized);
    assert!(nothing.is_empty());
    Ok(())
}


fn inbound_of(items: Vec<Result<(ShellFrame, usize), Status>>) -> ShellInbound {
    Box::pin(stream::iter(items))
}


fn wire_of(frame: &ShellFrame) -> usize {
    prost::Message::encoded_len(frame)
}


fn io_writer() -> (ShellWriter, tokio::io::DuplexStream) {
    let (writer, peer) = duplex(WRITER_ROOM);
    (Box::new(writer), peer)
}


#[tokio::test(start_paused = true)]
async fn a_server_that_never_sends_ends_at_the_dead_interval() -> TestResult {
    let (mut writer, _peer) = io_writer();
    let started = tokio::time::Instant::now();
    let ended = bounded(pump(Box::pin(stream::pending()), &mut writer)).await?;
    assert_eq!(ended, ShellClientEnd::Dead);
    assert_eq!(started.elapsed().as_secs(), SHELL_DEAD_SECONDS);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_writer_that_never_takes_the_input_ends_at_its_deadline() -> TestResult {
    let (tiny, _unread) = duplex(TINY_ROOM);
    let mut writer: ShellWriter = Box::new(tiny);
    let frame = data_frame(b"too much for the room");
    let wire = wire_of(&frame);
    let started = tokio::time::Instant::now();
    let ended = bounded(pump(inbound_of(vec![Ok((frame, wire))]), &mut writer)).await?;
    assert_eq!(ended, ShellClientEnd::WriteTimeout);
    assert_eq!(started.elapsed().as_secs(), SHELL_WRITE_SECONDS);
    Ok(())
}


#[tokio::test]
async fn a_writer_that_fails_ends_the_attach() -> TestResult {
    let (mut writer, peer) = io_writer();
    drop(peer);
    let frame = data_frame(b"input");
    let wire = wire_of(&frame);
    assert_eq!(pump(inbound_of(vec![Ok((frame, wire))]), &mut writer).await, ShellClientEnd::WriteFailed);
    Ok(())
}


#[tokio::test]
async fn transport_errors_end_the_attach_with_a_fixed_kind() -> TestResult {
    let (mut writer, _peer) = io_writer();
    assert_eq!(
        pump(inbound_of(vec![Err(Status::internal(MARKER))]), &mut writer).await,
        ShellClientEnd::Transport
    );
    assert_eq!(
        pump(inbound_of(vec![Err(Status::out_of_range(MARKER))]), &mut writer).await,
        ShellClientEnd::Oversized
    );
    Ok(())
}


#[tokio::test]
async fn a_wire_length_that_differs_from_the_decoded_one_is_refused() -> TestResult {
    let (mut writer, mut peer) = io_writer();
    let frame = data_frame(b"input");
    let wire = wire_of(&frame) + 1;
    assert_eq!(
        pump(
            inbound_of(vec![Ok((frame.clone(), wire)), Ok((frame.clone(), wire_of(&frame)))]),
            &mut writer
        )
        .await,
        ShellClientEnd::Malformed
    );
    drop(writer);
    let mut written = Vec::new();
    peer.read_to_end(&mut written).await?;
    assert!(written.is_empty());
    assert_eq!(
        pump(inbound_of(vec![Ok((frame, usize::MAX))]), &mut io_writer().0).await,
        ShellClientEnd::Malformed
    );
    Ok(())
}


#[test]
fn the_server_frame_table_admits_only_data_resize_and_known_closes() -> TestResult {
    assert!(server_frame(data_frame(b"x")).is_some());
    assert!(server_frame(data_frame(&vec![0; MAX_SHELL_FRAME_BYTES])).is_some());
    assert!(server_frame(data_frame(&vec![0; MAX_SHELL_FRAME_BYTES + 1])).is_none());
    assert!(server_frame(resize_frame(1, 1)).is_some());
    assert!(server_frame(close_frame(i32::from(ShellCloseReason::ChannelDead))).is_some());
    assert!(!is_known_reason(0));
    assert!(!is_known_reason(UNKNOWN_REASON));
    assert!([
        open_frame(SESSION),
        keepalive_frame(),
        empty_frame(),
        resize_frame(1, 0),
        resize_frame(0, 1)
    ]
    .into_iter()
    .all(|frame| server_frame(frame).is_none()));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_attach_opens_first_and_sends_a_keepalive_every_interval() -> TestResult {
    let mut frames = Box::pin(outbound_frames(SESSION, silent_reader()));
    assert_eq!(frames.next().await, Some(open_frame(SESSION)));
    let started = tokio::time::Instant::now();
    assert_eq!(frames.next().await, Some(keepalive_frame()));
    assert_eq!(started.elapsed().as_secs(), SHELL_KEEPALIVE_SECONDS);
    assert_eq!(frames.next().await, Some(keepalive_frame()));
    assert_eq!(started.elapsed().as_secs(), SHELL_KEEPALIVE_SECONDS * TWO_PERIODS);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_stalled_consumer_gets_one_keepalive_then_the_normal_pace_not_a_burst() -> TestResult {
    let mut frames = Box::pin(outbound_frames(SESSION, silent_reader()));
    assert_eq!(frames.next().await, Some(open_frame(SESSION)));
    tokio::time::sleep(std::time::Duration::from_secs(SHELL_KEEPALIVE_SECONDS * STALLED_PERIODS)).await;
    assert_eq!(frames.next().await, Some(keepalive_frame()));
    let resumed = tokio::time::Instant::now();
    assert_eq!(frames.next().await, Some(keepalive_frame()));
    assert_eq!(resumed.elapsed().as_secs(), SHELL_KEEPALIVE_SECONDS);
    Ok(())
}


#[tokio::test]
async fn a_long_read_is_split_and_the_end_of_output_closes_as_exited() -> TestResult {
    let output: ShellReader = Box::pin(stream::iter(vec![Ok(vec![FILL_BYTE; READ_ALL_BYTES]), Ok(Vec::new())]));
    let frames = outbound_frames(SESSION, output).collect::<Vec<_>>().await;
    let sizes: Vec<usize> = frames
        .iter()
        .filter_map(|frame| match &frame.frame {
            Some(Frame::Data(bytes)) => Some(bytes.len()),
            _ => None,
        })
        .collect();
    let mut expected = vec![MAX_SHELL_FRAME_BYTES; FULL_CHUNKS];
    expected.push(LAST_CHUNK_BYTES);
    assert_eq!(sizes, expected);
    assert_eq!(frames.first(), Some(&open_frame(SESSION)));
    assert_eq!(frames.last(), Some(&client_close(ShellCloseReason::Exited)));
    assert_eq!(frames.len(), sizes.len() + OPEN_AND_CLOSE);
    assert_eq!(data_frames(b"").len(), 0);
    Ok(())
}


#[tokio::test]
async fn a_failed_read_closes_as_an_agent_error_and_is_not_read_again() -> TestResult {
    let output: ShellReader = Box::pin(stream::iter(vec![
        Ok(b"a".to_vec()),
        Err(io::Error::other(MARKER)),
        Ok(b"never".to_vec()),
    ]));
    let frames = outbound_frames(SESSION, output).collect::<Vec<_>>().await;
    assert_eq!(
        frames,
        vec![open_frame(SESSION), data_frame(b"a"), client_close(ShellCloseReason::AgentError)]
    );
    Ok(())
}
