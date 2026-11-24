use crate::harness::long_tempdir;
use crate::harness::{bounded, client_paths, empty_revocation, make_platform, server_paths, start_server_routed, stop_server, Platform};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::services::{agent_identity, counter};
use crate::shell_rig::{approve, close_frame, data_frame, open_frame, rig, Rig, SESSION};
use crate::types::TestResult;
use agent_channel::client::{connect_channel, ready_grpc};
use agent_channel::model::{AgentCloseReason, ShellEnd, ShellSinkEvent, MAX_SHELL_FRAME_BYTES, MAX_SHELL_MESSAGE_BYTES, SHELL_PATH};
use agent_channel::proto::{ShellCloseReason, ShellFrame, ShellKeepalive, ShellOpen};
use agent_channel::shell::shell_router;
use agent_channel::tls::client_config;
use futures_util::{stream, StreamExt};
use http::uri::PathAndQuery;
use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpListener;
use tonic::Code;
use tonic_prost::ProstCodec;


const RACING_ATTACHES: usize = 4;


const PADDING_BYTES: usize = 524_288;


const PADDING_FRAMING_BYTES: usize = 7;


const KEEPALIVE_FLOOD: usize = 1_000;


const SMALL_DATA_BYTES: usize = 10;


#[derive(Clone, PartialEq, prost::Message)]
pub struct Padded {
    #[prost(message, optional, tag = "1")]
    pub open: Option<ShellOpen>,
    #[prost(bytes = "vec", tag = "99")]
    pub padding: Vec<u8>,
}


#[derive(Clone, PartialEq, prost::Message)]
pub struct Mixed {
    #[prost(message, optional, tag = "1")]
    pub open: Option<ShellOpen>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub data: Option<Vec<u8>>,
    #[prost(message, optional, tag = "4")]
    pub keepalive: Option<ShellKeepalive>,
    #[prost(bytes = "vec", tag = "99")]
    pub padding: Vec<u8>,
}


fn mixed_open(unknown: usize) -> Mixed {
    Mixed {
        open: Some(ShellOpen {
            session_id: SESSION.to_string(),
        }),
        data: None,
        keepalive: None,
        padding: vec![0; unknown],
    }
}


fn padded_keepalive() -> Mixed {
    Mixed {
        open: None,
        data: None,
        keepalive: Some(ShellKeepalive {}),
        padding: vec![0; MAX_SHELL_MESSAGE_BYTES - PADDING_FRAMING_BYTES],
    }
}


fn mixed_data(bytes: &[u8], unknown: usize) -> Mixed {
    Mixed {
        open: None,
        data: Some(bytes.to_vec()),
        keepalive: None,
        padding: vec![0; unknown],
    }
}


async fn over_tls<Message>(rig: &mut Rig, messages: Vec<Message>) -> Result<Vec<ShellSinkEvent>, Box<dyn Error>>
where
    Message: prost::Message + Send + 'static,
{
    Ok(over_tls_full(rig, messages).await?.0)
}


async fn over_tls_full<Message>(rig: &mut Rig, messages: Vec<Message>) -> Result<(Vec<ShellSinkEvent>, crate::types::Received), Box<dyn Error>>
where
    Message: prost::Message + Send + 'static,
{
    let dir = long_tempdir()?;
    let platform: Platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let router = shell_router(Arc::clone(&rig.state), Arc::clone(&rig.shell));
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
    let mut grpc = ready_grpc(channel).await?;
    let response = grpc
        .streaming(
            tonic::Request::new(stream::iter(messages)),
            PathAndQuery::from_static(SHELL_PATH),
            ProstCodec::<Message, ShellFrame>::default(),
        )
        .await?;
    let received = bounded(response.into_inner().collect::<Vec<_>>()).await?;
    let events = crate::shell_rig::until_ended(rig).await?;
    assert!(received.len() <= 1);
    stop_server(server).await?;
    Ok((events, received))
}


#[tokio::test]
async fn a_frame_padded_with_unknown_fields_is_refused_by_the_codec_not_buffered() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let open = Padded {
        open: Some(ShellOpen {
            session_id: SESSION.to_string(),
        }),
        padding: Vec::new(),
    };
    let padded = Padded {
        open: None,
        padding: vec![0; PADDING_BYTES],
    };
    let (events, received) = over_tls_full(&mut rig, vec![open, padded]).await?;
    assert_eq!(events, vec![ShellSinkEvent::Ended(ShellEnd::Oversized)]);
    let status = received.into_iter().next().ok_or("no status")?.err().ok_or("a clean end")?;
    assert_eq!(status.code(), Code::OutOfRange);
    assert_eq!(counter(&rig.state.counters.oversized), 1);
    Ok(())
}


#[tokio::test]
async fn the_largest_valid_data_frame_passes_the_codec() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let frames = vec![
        open_frame(SESSION),
        data_frame(&vec![1; MAX_SHELL_FRAME_BYTES]),
        close_frame(i32::from(ShellCloseReason::Exited)),
    ];
    let events = over_tls(&mut rig, frames).await?;
    assert_eq!(
        events,
        vec![
            ShellSinkEvent::Output(vec![1; MAX_SHELL_FRAME_BYTES]),
            ShellSinkEvent::Ended(ShellEnd::AgentClosed(AgentCloseReason::Exited)),
        ]
    );
    assert_eq!(counter(&rig.state.counters.oversized), 0);
    assert_eq!(agent_identity().agent_id, "agent-1");
    Ok(())
}


#[tokio::test]
async fn an_attach_without_an_approved_session_is_refused_over_tls() -> TestResult {
    let mut rig = rig();
    let outcome = over_tls(&mut rig, vec![open_frame(SESSION)]).await;
    assert!(outcome.is_err());
    assert_eq!(counter(&rig.state.counters.shell_unexpected), 1);
    Ok(())
}


#[tokio::test]
async fn a_resize_from_the_agent_over_tls_ends_the_stream_with_a_fixed_status() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let frames = vec![open_frame(SESSION), crate::shell_rig::resize_frame(1, 1), data_frame(b"after")];
    let events = over_tls(&mut rig, frames).await?;
    assert_eq!(events, vec![ShellSinkEvent::Ended(ShellEnd::Malformed)]);
    Ok(())
}


#[tokio::test]
async fn two_attaches_racing_for_one_session_over_tls_open_exactly_one() -> TestResult {
    let rig = rig();
    approve(&rig, SESSION)?;
    let dir = long_tempdir()?;
    let platform: Platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let router = shell_router(Arc::clone(&rig.state), Arc::clone(&rig.shell));
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
    let attempts = futures_util::future::join_all((0..RACING_ATTACHES).map(|_racer| {
        let racing = channel.clone();
        async move {
            let mut grpc = ready_grpc(racing).await?;
            Ok::<_, Box<dyn Error>>(
                grpc.streaming(
                    tonic::Request::new(stream::iter(vec![open_frame(SESSION)])),
                    PathAndQuery::from_static(SHELL_PATH),
                    ProstCodec::<ShellFrame, ShellFrame>::default(),
                )
                .await
                .is_ok(),
            )
        }
    }))
    .await;
    let accepted = attempts.into_iter().filter(|attempt| matches!(attempt, Ok(true))).count();
    assert_eq!(accepted, 1);
    assert_eq!(counter(&rig.state.counters.shell_opened), 1);
    stop_server(server).await?;
    Ok(())
}


#[tokio::test]
async fn a_keepalive_padded_with_an_unknown_field_just_under_the_limit_ends_the_session() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    assert_eq!(prost::Message::encoded_len(&padded_keepalive()), MAX_SHELL_MESSAGE_BYTES);
    let mut frames = vec![mixed_open(0)];
    frames.extend((0..KEEPALIVE_FLOOD).map(|_flood| padded_keepalive()));
    let (events, received) = over_tls_full(&mut rig, frames).await?;
    assert_eq!(events, vec![ShellSinkEvent::Ended(ShellEnd::Malformed)]);
    assert_eq!(counter(&rig.state.counters.shell_malformed), 1);
    assert_eq!(counter(&rig.state.counters.shell_budget), 0);
    let status = received.into_iter().next().ok_or("no status")?.err().ok_or("a clean end")?;
    assert_eq!(status.code(), Code::InvalidArgument);
    Ok(())
}


#[tokio::test]
async fn a_data_frame_padded_by_one_unknown_byte_ends_the_session_and_forwards_nothing() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let frames = vec![
        mixed_open(0),
        mixed_data(&[1; SMALL_DATA_BYTES], 0),
        mixed_data(&[1; SMALL_DATA_BYTES], 1),
        mixed_data(b"after", 0),
    ];
    let events = over_tls(&mut rig, frames).await?;
    assert_eq!(
        events,
        vec![
            ShellSinkEvent::Output(vec![1; SMALL_DATA_BYTES]),
            ShellSinkEvent::Ended(ShellEnd::Malformed)
        ]
    );
    Ok(())
}


#[tokio::test]
async fn an_open_frame_with_an_unknown_field_is_refused() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let outcome = over_tls(&mut rig, vec![mixed_open(1)]).await;
    assert!(outcome.is_err());
    assert_eq!(counter(&rig.state.counters.shell_malformed), 1);
    assert_eq!(counter(&rig.state.counters.shell_opened), 0);
    Ok(())
}
