#[path = "support/types.rs"]
mod types;


use site_collector::error::SpoolError;
use site_collector::frame::{encode_frame, frame_crc, frame_len, priority_byte, priority_from_byte, read_frame};
use site_collector::spool_model::{FrameRead, Priority, Record, FRAME_HEADER_BYTES, MAX_PAYLOAD_BYTES};
use std::io::{self, Cursor, Read};
use types::TestResult;


const BIG: u64 = 1_000_000;


const UNKNOWN_PRIORITY: u8 = 7;


const SEQUENCE: u64 = 9;


const LEN_FIELD_BYTES: usize = 4;


const PRIORITY_OFFSET: usize = 4;


const SHORT_REST: usize = 3;


const CLAIMED_PAYLOAD: u32 = 100;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }
}


fn sample() -> Record {
    Record {
        priority: Priority::High,
        sequence: SEQUENCE,
        payload: b"hello".to_vec(),
    }
}


fn read_all(bytes: Vec<u8>) -> Result<FrameRead, SpoolError> {
    let remaining = bytes.len() as u64;
    read_frame(&mut Cursor::new(bytes), remaining)
}


#[test]
fn a_frame_round_trips() -> TestResult {
    let record = sample();
    let bytes = encode_frame(&record)?;
    assert_eq!(bytes.len() as u64, frame_len(record.payload.len()));
    let total = bytes.len() as u64;
    assert_eq!(read_all(bytes)?, FrameRead::Frame(record, total));
    Ok(())
}


#[test]
fn priority_bytes_round_trip() -> TestResult {
    assert_eq!(priority_from_byte(priority_byte(Priority::Low)), Some(Priority::Low));
    assert_eq!(priority_from_byte(priority_byte(Priority::High)), Some(Priority::High));
    assert_eq!(priority_from_byte(UNKNOWN_PRIORITY), None);
    Ok(())
}


#[test]
fn an_oversized_payload_is_refused() -> TestResult {
    let record = Record {
        priority: Priority::Low,
        sequence: 0,
        payload: vec![0; MAX_PAYLOAD_BYTES + 1],
    };
    assert!(matches!(encode_frame(&record), Err(SpoolError::PayloadTooLarge)));
    Ok(())
}


#[test]
fn nothing_left_is_the_end_and_a_short_rest_is_torn() -> TestResult {
    assert_eq!(read_frame(&mut Cursor::new(Vec::new()), 0)?, FrameRead::End);
    assert_eq!(read_all(vec![1; SHORT_REST])?, FrameRead::Torn);
    Ok(())
}


#[test]
fn a_lying_length_is_refused_before_reading_the_payload() -> TestResult {
    let mut huge = encode_frame(&sample())?;
    huge.splice(0..LEN_FIELD_BYTES, u32::MAX.to_le_bytes());
    assert_eq!(read_frame(&mut Cursor::new(huge), BIG)?, FrameRead::Torn);
    let mut just_over = encode_frame(&sample())?;
    just_over.splice(0..LEN_FIELD_BYTES, u32::try_from(MAX_PAYLOAD_BYTES + 1)?.to_le_bytes());
    assert_eq!(read_frame(&mut Cursor::new(just_over), BIG)?, FrameRead::Torn);
    let mut beyond_end = encode_frame(&sample())?;
    beyond_end.splice(0..LEN_FIELD_BYTES, CLAIMED_PAYLOAD.to_le_bytes());
    assert_eq!(read_all(beyond_end)?, FrameRead::Torn);
    Ok(())
}


#[test]
fn a_bad_checksum_or_priority_is_torn() -> TestResult {
    let mut flipped = encode_frame(&sample())?;
    let last = flipped.len() - 1;
    flipped.get_mut(last).map(|byte| *byte ^= 1).ok_or("empty frame")?;
    assert_eq!(read_all(flipped)?, FrameRead::Torn);

    let mut unknown = encode_frame(&sample())?;
    unknown
        .get_mut(PRIORITY_OFFSET)
        .map(|byte| *byte = UNKNOWN_PRIORITY)
        .ok_or("short frame")?;
    let crc = frame_crc(UNKNOWN_PRIORITY, SEQUENCE, b"hello").to_le_bytes();
    unknown.splice(FRAME_HEADER_BYTES - LEN_FIELD_BYTES..FRAME_HEADER_BYTES, crc);
    assert_eq!(read_all(unknown)?, FrameRead::Torn);
    Ok(())
}


#[test]
fn a_failing_reader_is_an_error() -> TestResult {
    assert!(matches!(read_frame(&mut FailingReader, BIG), Err(SpoolError::Io(_))));
    Ok(())
}
