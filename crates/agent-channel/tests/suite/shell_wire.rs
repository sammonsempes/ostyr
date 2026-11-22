use crate::types::TestResult;
use agent_channel::model::WireScan;
use agent_channel::shell_wire::{new_wire_lengths, pop_wire_length, scan_chunk, scanned_body};
use axum::body::{Body, Bytes};
use futures_util::{stream, StreamExt};
use std::io;


const FIRST_LENGTH: usize = 3;


const SECOND_LENGTH: usize = 300;


const BIG_LENGTH: u32 = 70_000;


const PREFIX_BYTES: usize = 5;


const FILL: u8 = 7;


fn message(length: usize) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend(u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes());
    bytes.extend(vec![FILL; length]);
    bytes
}


fn two_messages() -> Vec<u8> {
    let mut bytes = message(FIRST_LENGTH);
    bytes.extend(message(SECOND_LENGTH));
    bytes
}


#[test]
fn a_whole_chunk_records_every_message_length() -> TestResult {
    let lengths = new_wire_lengths();
    let scan = scan_chunk(WireScan::default(), &two_messages(), &lengths);
    assert_eq!(scan, WireScan::default());
    assert_eq!(pop_wire_length(&lengths), FIRST_LENGTH);
    assert_eq!(pop_wire_length(&lengths), SECOND_LENGTH);
    assert_eq!(pop_wire_length(&lengths), usize::MAX);
    Ok(())
}


#[test]
fn any_split_of_the_stream_records_the_same_lengths() -> TestResult {
    let bytes = two_messages();
    (0..=bytes.len()).try_for_each(|cut| -> TestResult {
        let lengths = new_wire_lengths();
        let (head, tail) = bytes.split_at(cut);
        let scan = scan_chunk(scan_chunk(WireScan::default(), head, &lengths), tail, &lengths);
        assert_eq!(scan, WireScan::default());
        assert_eq!(pop_wire_length(&lengths), FIRST_LENGTH);
        assert_eq!(pop_wire_length(&lengths), SECOND_LENGTH);
        Ok(())
    })
}


#[test]
fn a_prefix_announces_its_length_before_the_message_body_arrives() -> TestResult {
    let lengths = new_wire_lengths();
    let prefix = message(0).into_iter().take(PREFIX_BYTES - 1).collect::<Vec<_>>();
    let partial = scan_chunk(WireScan::default(), &prefix, &lengths);
    assert_eq!(pop_wire_length(&lengths), usize::MAX);
    assert_eq!(partial.prefix_seen, u8::try_from(PREFIX_BYTES - 1)?);
    let mut header = vec![0];
    header.extend(BIG_LENGTH.to_be_bytes());
    let announced = scan_chunk(WireScan::default(), &header, &lengths);
    assert_eq!(announced.remaining, BIG_LENGTH);
    assert_eq!(pop_wire_length(&lengths), usize::try_from(BIG_LENGTH)?);
    Ok(())
}


#[tokio::test]
async fn the_scanned_body_passes_every_byte_and_error_through() -> TestResult {
    let lengths = new_wire_lengths();
    let bytes = two_messages();
    let chunks: Vec<Result<Bytes, io::Error>> = vec![Ok(Bytes::from(bytes.clone())), Err(io::Error::other("reset"))];
    let body = scanned_body(Body::from_stream(stream::iter(chunks)), lengths.clone());
    let seen = body.into_data_stream().collect::<Vec<_>>().await;
    assert_eq!(seen.iter().filter(|item| item.is_err()).count(), 1);
    let passed: Vec<u8> = seen.into_iter().flatten().flat_map(|chunk| chunk.to_vec()).collect();
    assert_eq!(passed, bytes);
    assert_eq!(pop_wire_length(&lengths), FIRST_LENGTH);
    assert_eq!(pop_wire_length(&lengths), SECOND_LENGTH);
    Ok(())
}
