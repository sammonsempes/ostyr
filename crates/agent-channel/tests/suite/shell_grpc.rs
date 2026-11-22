use crate::services::{agent_identity, counter};
use crate::shell_rig::{approve, data_frame, keepalive_frame, open_frame, rig, until_ended, SESSION};
use crate::types::TestResult;
use agent_channel::model::{ShellEnd, ShellSinkEvent, MAX_SHELL_FRAMES_PER_SECOND, SHELL_PATH};
use agent_channel::proto::ShellFrame;
use agent_channel::shell::shell_route;
use axum::body::{Body, Bytes};
use futures_util::stream;
use http::Request;
use prost::Message;
use std::io;
use std::sync::Arc;


const CHUNK_SIZES: [usize; 5] = [1, 3, 64, 4_096, 1_048_576];


const GARBAGE: &[u8] = &[0xff, 0xff, 0xff];


const EVENTS_BEFORE_END: usize = 2;


const NON_CANONICAL_CLOSE: &[u8] = &[0x2a, 0x03, 0x08, 0x81, 0x00];


const BURST: usize = 2_300;


const OVERSIZED_PAYLOAD: usize = 70_000;


const PREFIX_BYTES: usize = 5;


const SHORT_BODY_BYTES: usize = 3;


const ANNOUNCED_BYTES: u32 = 10;


const BAD_FLAG: u8 = 7;


const COMPRESSED_FLAG: u8 = 1;


fn grpc(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flag];
    bytes.extend(u32::try_from(payload.len()).unwrap_or(u32::MAX).to_be_bytes());
    bytes.extend(payload);
    bytes
}


fn message(frame: &ShellFrame) -> Vec<u8> {
    grpc(0, &frame.encode_to_vec())
}


fn chunked(bytes: Vec<u8>, size: usize) -> Vec<Result<Bytes, io::Error>> {
    bytes.chunks(size).map(|chunk| Ok(Bytes::copy_from_slice(chunk))).collect()
}


async fn feed(body: Vec<u8>, size: usize) -> Result<(Vec<ShellSinkEvent>, u64, u64), Box<dyn std::error::Error>> {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let mut request = Request::builder()
        .method("POST")
        .uri(SHELL_PATH)
        .header("content-type", "application/grpc")
        .body(Body::from_stream(stream::iter(chunked(body, size))))?;
    request.extensions_mut().insert(agent_identity());
    let response = shell_route(Arc::clone(&rig.state), Arc::clone(&rig.shell), request).await?;
    let events = until_ended(&mut rig).await?;
    drop(response);
    Ok((
        events,
        counter(&rig.state.counters.shell_malformed),
        counter(&rig.state.counters.oversized),
    ))
}


fn session_then(rest: Vec<u8>) -> Vec<u8> {
    let mut bytes = message(&open_frame(SESSION));
    bytes.extend(rest);
    bytes
}


async fn ends_with_for_every_chunk(body: Vec<u8>, expected: ShellEnd) -> TestResult {
    for size in CHUNK_SIZES {
        let (events, _malformed, _oversized) = feed(body.clone(), size).await?;
        assert_eq!(events, vec![ShellSinkEvent::Ended(expected)], "chunk size {size}");
    }
    Ok(())
}


#[tokio::test]
async fn a_compressed_message_ends_the_session_and_nothing_after_it_is_forwarded() -> TestResult {
    let mut rest = grpc(COMPRESSED_FLAG, &data_frame(b"x").encode_to_vec());
    rest.extend(message(&data_frame(b"after")));
    ends_with_for_every_chunk(session_then(rest), ShellEnd::Transport).await
}


#[tokio::test]
async fn a_bad_compression_flag_ends_the_session() -> TestResult {
    let mut rest = grpc(BAD_FLAG, &data_frame(b"x").encode_to_vec());
    rest.extend(message(&data_frame(b"after")));
    ends_with_for_every_chunk(session_then(rest), ShellEnd::Transport).await
}


#[tokio::test]
async fn a_zero_length_message_is_a_frame_with_no_member() -> TestResult {
    let mut rest = grpc(0, &[]);
    rest.extend(message(&data_frame(b"after")));
    ends_with_for_every_chunk(session_then(rest), ShellEnd::Malformed).await
}


#[tokio::test]
async fn a_protobuf_decode_error_mid_stream_ends_the_session() -> TestResult {
    let mut rest = message(&data_frame(b"before"));
    rest.extend(grpc(0, GARBAGE));
    rest.extend(message(&data_frame(b"after")));
    for size in CHUNK_SIZES {
        let (events, _malformed, _oversized) = feed(session_then(rest.clone()), size).await?;
        assert_eq!(
            events,
            vec![ShellSinkEvent::Output(b"before".to_vec()), ShellSinkEvent::Ended(ShellEnd::Transport)],
            "chunk size {size}"
        );
    }
    Ok(())
}


#[tokio::test]
async fn an_oversized_message_mid_stream_ends_the_session_as_oversized() -> TestResult {
    let mut rest = message(&data_frame(b"before"));
    rest.extend(grpc(0, &vec![0; OVERSIZED_PAYLOAD]));
    rest.extend(message(&data_frame(b"after")));
    for size in CHUNK_SIZES {
        let (events, _malformed, oversized) = feed(session_then(rest.clone()), size).await?;
        assert_eq!(
            events,
            vec![ShellSinkEvent::Output(b"before".to_vec()), ShellSinkEvent::Ended(ShellEnd::Oversized)],
            "chunk size {size}"
        );
        assert_eq!(oversized, 1);
    }
    Ok(())
}


#[tokio::test]
async fn a_burst_of_keepalives_in_one_chunk_ends_at_the_frame_budget() -> TestResult {
    let burst: Vec<u8> = (0..BURST).flat_map(|_keepalive| message(&keepalive_frame())).collect();
    let mut rest = burst;
    rest.extend(message(&data_frame(b"after")));
    for size in CHUNK_SIZES {
        let (events, _malformed, _oversized) = feed(session_then(rest.clone()), size).await?;
        let ticks = usize::try_from(MAX_SHELL_FRAMES_PER_SECOND)?;
        assert_eq!(events.len(), ticks + 1, "chunk size {size}");
        assert!(events.iter().take(ticks).all(|event| *event == ShellSinkEvent::Tick));
        assert_eq!(events.last(), Some(&ShellSinkEvent::Ended(ShellEnd::Budget)));
    }
    Ok(())
}


#[tokio::test]
async fn a_truncated_last_message_ends_the_session() -> TestResult {
    let mut rest = message(&data_frame(b"before"));
    let mut cut = vec![0];
    cut.extend(ANNOUNCED_BYTES.to_be_bytes());
    cut.extend(vec![0; SHORT_BODY_BYTES]);
    assert_eq!(cut.len(), PREFIX_BYTES + SHORT_BODY_BYTES);
    rest.extend(cut);
    for size in CHUNK_SIZES {
        let (events, _malformed, _oversized) = feed(session_then(rest.clone()), size).await?;
        assert_eq!(events.first(), Some(&ShellSinkEvent::Output(b"before".to_vec())), "chunk size {size}");
        assert_eq!(events.len(), EVENTS_BEFORE_END, "chunk size {size}");
        assert!(matches!(events.last(), Some(ShellSinkEvent::Ended(ShellEnd::Transport))));
    }
    Ok(())
}


#[tokio::test]
async fn a_short_non_canonical_close_is_refused() -> TestResult {
    let mut rest = grpc(0, NON_CANONICAL_CLOSE);
    rest.extend(message(&data_frame(b"after")));
    for size in CHUNK_SIZES {
        let (events, malformed, _oversized) = feed(session_then(rest.clone()), size).await?;
        assert_eq!(events, vec![ShellSinkEvent::Ended(ShellEnd::Malformed)], "chunk size {size}");
        assert_eq!(malformed, 1);
    }
    Ok(())
}
