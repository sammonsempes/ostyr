mod common;


use common::types::TestResult;
use remote_shell::recording::{
    check_limits, close, encode_frame, frame_hash, new_writer, parse_body, parse_payload, push, read_recording, Check, Direction, FramePayload,
    Header, Limits, Recording, RecordingError, DEFAULT_MAX_FRAMES, FIXED_BODY_BYTES, GENESIS_HASH, MAX_BODY_BYTES, MAX_FIELD_BYTES,
    MAX_FRAMES_CEILING, MAX_FRAME_BYTES, MAX_REASON_BYTES, MAX_RECORDING_BYTES_CEILING, PREFIX_BYTES,
};
use remote_shell::types::ChainHash;
use std::io::{self, Read, Write};


const START: i64 = 1_000;


const MEMORY_LIMIT_ENV: &str = "REMOTE_SHELL_RECORDING_MEMORY_CHILD";


const MEMORY_LIMIT_BYTES: &str = "--as=2147483648";


const MEMORY_FLOOD_FRAMES: u64 = 200_000;


const MEMORY_FLOOD_CAP: u64 = 100_000;


const AT_LS: i64 = START + 1;


const AT_FILE: i64 = AT_LS + 1;


const AT_EXIT: i64 = AT_FILE + 1;


const AT_CLOSE: i64 = AT_EXIT + 1;


const BIG_FRAME: usize = 30_000;


const BIG_FRAMES: usize = 3;


const FRAME_COUNT: u64 = 5;


const TRAILER_SEQ: u64 = FRAME_COUNT - 1;


const DATA_FRAMES: usize = 3;


const KEPT_WITHOUT_TRAILER: usize = 4;


const PREFIX_LEN: usize = 4;


const FIELD_SETTERS: usize = 4;


const SWAPPED_ORDER: [usize; 5] = [0, 2, 1, 3, 4];


const BASE_AT: i64 = 100;


const BEFORE_BASE_AT: i64 = 99;


const SEQ_SKIPPED: u64 = 2;


const HOSTILE_PADDING: usize = 96;


const FLOOD_CAP: u64 = 1_000;


const SMALL_FRAME_CAP: u64 = 3;


const MAX_SPLIT_FRAMES: usize = 100;


const KIND_HEADER: u8 = 0;


const KIND_DATA: u8 = 1;


const KIND_TRAILER: u8 = 2;


const KIND_UNKNOWN: u8 = 9;


const DIRECTION_UNKNOWN: u8 = 7;


const BAD_VERSION: u8 = 2;


const GOOD_VERSION: u8 = 1;


const BYTE_FF: u8 = 0xff;


const PAYLOAD_OFFSET: usize = 53;


const SERVED_FIRST_BYTE: usize = 0;


const SERVED_PREFIX_TAIL: usize = 1;


const SERVED_BODY: usize = 4;


pub struct FailingWrite {
    pub fail_flush_only: bool,
}


impl Write for FailingWrite {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail_flush_only {
            Ok(buffer.len())
        } else {
            Err(io::Error::other("injected"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected"))
    }
}


pub struct FailAfter {
    pub data: Vec<u8>,
    pub served: usize,
}


impl Read for FailAfter {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining: Vec<u8> = self.data.iter().skip(self.served).copied().collect();
        if remaining.is_empty() {
            Err(io::Error::other("injected"))
        } else {
            let count = remaining.len().min(buffer.len());
            buffer.iter_mut().zip(remaining.iter()).for_each(|(target, source)| *target = *source);
            self.served += count;
            Ok(count)
        }
    }
}


fn header() -> Header {
    Header {
        session_id: "req-1".to_string(),
        tenant: "tenant-a".to_string(),
        requester: "alice".to_string(),
        asset: "asset-1".to_string(),
        ticket: "TICKET-1".to_string(),
        opened_at: START,
    }
}


fn sample() -> Result<(Vec<u8>, ChainHash), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), Limits::default())?;
    push(&mut writer, Direction::In, b"ls\n", AT_LS)?;
    push(&mut writer, Direction::Out, b"file-a\n", AT_FILE)?;
    push(&mut writer, Direction::In, b"exit\n", AT_EXIT)?;
    let hash = close(&mut writer, "user", AT_CLOSE)?;
    Ok((out, hash))
}


fn read(bytes: &[u8], limits: &Limits) -> Result<Recording, RecordingError> {
    let mut reader = bytes;
    read_recording(&mut reader, limits)
}


fn prefix_of(bytes: &[u8], cut: usize) -> Vec<u8> {
    bytes.iter().take(cut).copied().collect()
}


fn split_frames(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut rest = bytes;
    let mut frames = Vec::new();
    while !rest.is_empty() && frames.len() < MAX_SPLIT_FRAMES {
        let (prefix, _) = rest.split_at_checked(PREFIX_LEN).ok_or("short prefix")?;
        let mut raw = [0; PREFIX_LEN];
        raw.copy_from_slice(prefix);
        let length = usize::try_from(u32::from_le_bytes(raw))? + PREFIX_LEN;
        let (frame, next) = rest.split_at_checked(length).ok_or("short frame")?;
        frames.push(frame.to_vec());
        rest = next;
    }
    Ok(frames)
}


fn join(frames: &[&Vec<u8>]) -> Vec<u8> {
    frames.iter().flat_map(|frame| frame.iter().copied()).collect()
}


fn forge(frames: &[(u64, i64, FramePayload)]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut prev = GENESIS_HASH;
    let mut out = Vec::new();
    for (seq, at, payload) in frames {
        let frame = encode_frame(&prev, *seq, *at, payload)?;
        prev = frame_hash(&frame);
        out.extend_from_slice(&frame);
    }
    Ok(out)
}


fn head_payload() -> FramePayload {
    FramePayload::Header(header())
}


fn data_payload() -> FramePayload {
    FramePayload::Data {
        direction: Direction::In,
        bytes: b"x".to_vec(),
    }
}


fn trailer_payload() -> FramePayload {
    FramePayload::Trailer { reason: "user".to_string() }
}


fn expect(result: Result<Recording, RecordingError>, expected_frame: u64, expected_check: Check) {
    assert!(
        matches!(&result, Err(RecordingError::Frame { frame, check }) if *frame == expected_frame && *check == expected_check),
        "{result:?}"
    );
}


fn payload_of(payload: &FramePayload) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let frame = encode_frame(&GENESIS_HASH, 0, 0, payload)?;
    Ok(frame.iter().skip(PAYLOAD_OFFSET).copied().collect())
}


#[test]
fn a_round_trip_returns_everything_and_the_final_hash() -> TestResult {
    let (bytes, hash) = sample()?;
    let recording = read(&bytes, &Limits::default())?;
    assert_eq!(recording.header, header());
    assert_eq!(recording.final_hash, hash);
    assert_eq!(recording.frames.len(), DATA_FRAMES);
    assert_eq!(
        recording.frames.first().map(|frame| (frame.seq, frame.at, frame.direction)),
        Some((1, AT_LS, Direction::In))
    );
    assert_eq!(recording.frames.get(1).map(|frame| frame.bytes.clone()), Some(b"file-a\n".to_vec()));
    assert_eq!(recording.frames.get(1).map(|frame| frame.direction), Some(Direction::Out));
    assert_eq!(
        (recording.trailer.seq, recording.trailer.at, recording.trailer.reason.as_str()),
        (TRAILER_SEQ, AT_CLOSE, "user")
    );
    Ok(())
}


#[test]
fn a_removed_frame_is_a_broken_chain() -> TestResult {
    let (bytes, _) = sample()?;
    let frames = split_frames(&bytes)?;
    let kept: Vec<&Vec<u8>> = frames
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, frame)| frame)
        .collect();
    expect(read(&join(&kept), &Limits::default()), 1, Check::Chain);
    Ok(())
}


#[test]
fn two_swapped_frames_are_a_broken_chain() -> TestResult {
    let (bytes, _) = sample()?;
    let frames = split_frames(&bytes)?;
    let swapped: Vec<&Vec<u8>> = SWAPPED_ORDER.iter().filter_map(|index| frames.get(*index)).collect();
    expect(read(&join(&swapped), &Limits::default()), 1, Check::Chain);
    Ok(())
}


#[test]
fn a_flipped_body_byte_breaks_the_next_frame() -> TestResult {
    let (mut bytes, _) = sample()?;
    let frames = split_frames(&bytes)?;
    let offset = frames.first().map(Vec::len).ok_or("no frame")? + frames.get(1).map(Vec::len).ok_or("no frame")? - 1;
    let target = bytes.get_mut(offset).ok_or("offset")?;
    *target ^= 1;
    expect(read(&bytes, &Limits::default()), SEQ_SKIPPED, Check::Chain);
    Ok(())
}


#[test]
fn a_missing_trailer_and_a_truncated_frame_are_refused() -> TestResult {
    let (bytes, _) = sample()?;
    let frames = split_frames(&bytes)?;
    let without_trailer: Vec<&Vec<u8>> = frames.iter().take(KEPT_WITHOUT_TRAILER).collect();
    expect(read(&join(&without_trailer), &Limits::default()), TRAILER_SEQ, Check::TrailerMissing);
    expect(read(&[], &Limits::default()), 0, Check::Truncated);
    let refused = (0..bytes.len()).all(|cut| read(&prefix_of(&bytes, cut), &Limits::default()).is_err());
    assert!(refused);
    Ok(())
}


#[test]
fn time_going_back_and_a_skipped_sequence_are_refused() -> TestResult {
    let back = forge(&[(0, BASE_AT, head_payload()), (1, BEFORE_BASE_AT, data_payload())])?;
    expect(read(&back, &Limits::default()), 1, Check::Time);
    let skip = forge(&[(0, BASE_AT, head_payload()), (SEQ_SKIPPED, BASE_AT, data_payload())])?;
    expect(read(&skip, &Limits::default()), 1, Check::Sequence);
    let equal = forge(&[
        (0, BASE_AT, head_payload()),
        (1, BASE_AT, data_payload()),
        (SEQ_SKIPPED, BASE_AT, trailer_payload()),
    ])?;
    assert!(read(&equal, &Limits::default()).is_ok());
    Ok(())
}


#[test]
fn the_header_must_come_first_once_and_the_trailer_last() -> TestResult {
    let data_first = forge(&[(0, BASE_AT, data_payload())])?;
    expect(read(&data_first, &Limits::default()), 0, Check::Kind);
    let second_header = forge(&[(0, BASE_AT, head_payload()), (1, BASE_AT, head_payload())])?;
    expect(read(&second_header, &Limits::default()), 1, Check::Kind);
    let after_trailer = forge(&[
        (0, BASE_AT, head_payload()),
        (1, BASE_AT, trailer_payload()),
        (SEQ_SKIPPED, BASE_AT, data_payload()),
    ])?;
    expect(read(&after_trailer, &Limits::default()), SEQ_SKIPPED, Check::TrailingData);
    let (mut bytes, _) = sample()?;
    bytes.push(0);
    expect(read(&bytes, &Limits::default()), FRAME_COUNT, Check::TrailingData);
    Ok(())
}


#[test]
fn a_declared_length_is_checked_before_any_allocation() -> TestResult {
    let mut hostile = u32::MAX.to_le_bytes().to_vec();
    hostile.extend_from_slice(&[0; HOSTILE_PADDING]);
    expect(read(&hostile, &Limits::default()), 0, Check::Length);
    let above = (MAX_BODY_BYTES + 1).to_le_bytes();
    expect(read(&above, &Limits::default()), 0, Check::Length);
    let below = (FIXED_BODY_BYTES - 1).to_le_bytes();
    expect(read(&below, &Limits::default()), 0, Check::Length);
    Ok(())
}


#[test]
fn a_recording_over_max_frames_is_refused_at_exactly_cap_plus_one() -> TestResult {
    let (bytes, _) = sample()?;
    let limits = |max_frames| Limits {
        max_frames,
        ..Limits::default()
    };
    assert!(read(&bytes, &limits(FRAME_COUNT)).is_ok());
    expect(read(&bytes, &limits(FRAME_COUNT - 1)), TRAILER_SEQ, Check::Full);
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), limits(SMALL_FRAME_CAP))?;
    push(&mut writer, Direction::In, b"a", START)?;
    push(&mut writer, Direction::In, b"b", START)?;
    assert!(matches!(push(&mut writer, Direction::In, b"c", START), Err(RecordingError::Full)));
    Ok(())
}


#[test]
fn a_flood_of_empty_frames_stops_at_the_cap() -> TestResult {
    let limits = Limits {
        max_frames: FLOOD_CAP,
        ..Limits::default()
    };
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), limits)?;
    let pushed = (1..FLOOD_CAP).filter(|_| push(&mut writer, Direction::In, b"", START).is_ok()).count();
    assert_eq!(pushed as u64, FLOOD_CAP - 1);
    assert!(matches!(close(&mut writer, "x", START + 1), Err(RecordingError::Full)));
    Ok(())
}


pub struct BigRun {
    pub out: Vec<u8>,
    pub outcome: Result<(), RecordingError>,
}


fn big_recording(limits: Limits) -> Result<BigRun, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), limits)?;
    let big = vec![b'a'; BIG_FRAME];
    let outcome = (0..BIG_FRAMES).try_for_each(|_| push(&mut writer, Direction::Out, &big, START));
    let closed = outcome.and_then(|()| close(&mut writer, "user", START).map(|_hash| ()));
    Ok(BigRun { out, outcome: closed })
}


#[test]
fn the_byte_cap_refuses_at_exactly_cap_plus_one() -> TestResult {
    let BigRun { out: full, outcome: first } = big_recording(Limits::default())?;
    first?;
    let total = full.len() as u64;
    let exact = Limits {
        max_recording_bytes: total,
        ..Limits::default()
    };
    let short = Limits {
        max_recording_bytes: total - 1,
        ..Limits::default()
    };
    assert!(read(&full, &exact).is_ok());
    expect(read(&full, &short), TRAILER_SEQ, Check::Full);
    let BigRun { outcome: refused, .. } = big_recording(short)?;
    assert!(matches!(refused, Err(RecordingError::Full)));
    let BigRun {
        out: exact_bytes,
        outcome: accepted,
    } = big_recording(exact)?;
    accepted?;
    assert_eq!(exact_bytes, full);
    assert_eq!(PREFIX_BYTES as usize, PREFIX_LEN);
    Ok(())
}


#[test]
fn limits_outside_their_range_are_refused() -> TestResult {
    let valid = Limits::default();
    assert!(check_limits(&valid).is_ok());
    let cases = [
        Limits {
            max_recording_bytes: 0,
            ..valid
        },
        Limits {
            max_recording_bytes: MAX_RECORDING_BYTES_CEILING + 1,
            ..valid
        },
        Limits { max_frames: 1, ..valid },
        Limits {
            max_frames: MAX_FRAMES_CEILING + 1,
            ..valid
        },
    ];
    for limits in cases {
        assert!(matches!(check_limits(&limits), Err(RecordingError::Limits)));
        assert!(matches!(new_writer(&mut Vec::new(), &header(), limits), Err(RecordingError::Limits)));
        assert!(matches!(read(&[], &limits), Err(RecordingError::Limits)));
    }
    let ceiling = Limits {
        max_recording_bytes: MAX_RECORDING_BYTES_CEILING,
        max_frames: MAX_FRAMES_CEILING,
    };
    assert!(check_limits(&ceiling).is_ok());
    Ok(())
}


#[test]
fn writer_errors_are_returned() -> TestResult {
    let mut failing = FailingWrite { fail_flush_only: false };
    assert!(matches!(
        new_writer(&mut failing, &header(), Limits::default()),
        Err(RecordingError::Write(_))
    ));
    let mut flush_only = FailingWrite { fail_flush_only: true };
    let mut writer = new_writer(&mut flush_only, &header(), Limits::default())?;
    push(&mut writer, Direction::In, b"a", START)?;
    assert!(matches!(close(&mut writer, "x", START), Err(RecordingError::Write(_))));
    let mut out = Vec::new();
    let mut ok = new_writer(&mut out, &header(), Limits::default())?;
    close(&mut ok, "x", START)?;
    assert!(matches!(push(&mut ok, Direction::In, b"a", START), Err(RecordingError::Closed)));
    Ok(())
}


#[test]
fn the_writer_refuses_time_going_back_and_oversized_input() -> TestResult {
    let mut back_out = Vec::new();
    let mut back_writer = new_writer(&mut back_out, &header(), Limits::default())?;
    assert!(matches!(
        push(&mut back_writer, Direction::In, b"a", START - 1),
        Err(RecordingError::TimeWentBack)
    ));
    assert!(matches!(push(&mut back_writer, Direction::In, b"a", START), Err(RecordingError::Closed)));
    let mut big_out = Vec::new();
    let mut big_writer = new_writer(&mut big_out, &header(), Limits::default())?;
    assert!(matches!(
        push(&mut big_writer, Direction::In, &vec![0; MAX_FRAME_BYTES + 1], START),
        Err(RecordingError::FrameTooLarge)
    ));
    assert!(matches!(close(&mut big_writer, "x", START), Err(RecordingError::Closed)));
    assert!(matches!(
        push(&mut big_writer, Direction::In, &vec![0; MAX_FRAME_BYTES + 1], START),
        Err(RecordingError::Closed)
    ));
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), Limits::default())?;
    push(&mut writer, Direction::In, &vec![0; MAX_FRAME_BYTES], START)?;
    let long_header = Header {
        ticket: "t".repeat(MAX_FIELD_BYTES + 1),
        ..header()
    };
    assert!(matches!(
        new_writer(&mut Vec::new(), &long_header, Limits::default()),
        Err(RecordingError::FieldTooLong)
    ));
    let fields: [fn(Header, String) -> Header; FIELD_SETTERS] = [
        |header, text| Header { session_id: text, ..header },
        |header, text| Header { tenant: text, ..header },
        |header, text| Header { requester: text, ..header },
        |header, text| Header { asset: text, ..header },
    ];
    for set in fields {
        let too_long = set(header(), "t".repeat(MAX_FIELD_BYTES + 1));
        assert!(matches!(
            new_writer(&mut Vec::new(), &too_long, Limits::default()),
            Err(RecordingError::FieldTooLong)
        ));
    }
    let at_cap = Header {
        ticket: "t".repeat(MAX_FIELD_BYTES),
        ..header()
    };
    assert!(new_writer(&mut Vec::new(), &at_cap, Limits::default()).is_ok());
    let reason = "r".repeat(MAX_REASON_BYTES + 1);
    assert!(matches!(close(&mut writer, &reason, START), Err(RecordingError::FieldTooLong)));
    assert!(matches!(close(&mut writer, "x", START), Err(RecordingError::Closed)));
    Ok(())
}


pub struct LimitedWrite {
    pub received: Vec<u8>,
    pub room: usize,
    pub fail_flush: bool,
}


impl Write for LimitedWrite {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.room == 0 {
            Err(io::Error::other("injected"))
        } else {
            let count = buffer.len().min(self.room);
            self.received.extend(buffer.iter().take(count));
            self.room -= count;
            Ok(count)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::other("injected"))
        } else {
            Ok(())
        }
    }
}


#[test]
fn the_writer_latches_after_full() -> TestResult {
    let limits = Limits {
        max_recording_bytes: u64::from(MAX_BODY_BYTES),
        ..Limits::default()
    };
    let mut probe = Vec::new();
    new_writer(&mut probe, &header(), limits)?;
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), limits)?;
    let big = vec![b'a'; MAX_FRAME_BYTES];
    assert!(matches!(push(&mut writer, Direction::Out, &big, START), Err(RecordingError::Full)));
    assert!(matches!(push(&mut writer, Direction::In, b"a", START), Err(RecordingError::Closed)));
    assert!(matches!(close(&mut writer, "x", START), Err(RecordingError::Closed)));
    assert_eq!(out.len(), probe.len());
    Ok(())
}


#[test]
fn the_writer_latches_after_a_partial_write() -> TestResult {
    let header_len = {
        let mut probe = Vec::new();
        new_writer(&mut probe, &header(), Limits::default())?;
        probe.len()
    };
    let mut sink = LimitedWrite {
        received: Vec::new(),
        room: header_len + PREFIX_LEN,
        fail_flush: false,
    };
    let mut writer = new_writer(&mut sink, &header(), Limits::default())?;
    assert!(matches!(push(&mut writer, Direction::In, b"abc", START), Err(RecordingError::Write(_))));
    assert!(matches!(push(&mut writer, Direction::In, b"a", START), Err(RecordingError::Closed)));
    assert!(matches!(close(&mut writer, "x", START), Err(RecordingError::Closed)));
    assert_eq!(sink.received.len(), header_len + PREFIX_LEN);
    Ok(())
}


#[test]
fn the_writer_latches_after_a_failed_flush() -> TestResult {
    let mut probe = Vec::new();
    let mut probe_writer = new_writer(&mut probe, &header(), Limits::default())?;
    close(&mut probe_writer, "x", START)?;
    let mut sink = LimitedWrite {
        received: Vec::new(),
        room: usize::MAX,
        fail_flush: true,
    };
    let mut writer = new_writer(&mut sink, &header(), Limits::default())?;
    assert!(matches!(close(&mut writer, "x", START), Err(RecordingError::Write(_))));
    assert!(matches!(close(&mut writer, "y", START), Err(RecordingError::Closed)));
    assert_eq!(sink.received.len(), probe.len());
    Ok(())
}


pub struct SpyRead {
    pub data: Vec<u8>,
    pub served: usize,
    pub largest_buffer: usize,
}


impl Read for SpyRead {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.largest_buffer = self.largest_buffer.max(buffer.len());
        let remaining = self.data.iter().skip(self.served).take(buffer.len());
        let count = buffer.iter_mut().zip(remaining).map(|(target, source)| *target = *source).count();
        self.served += count;
        Ok(count)
    }
}


#[test]
fn a_hostile_length_never_sizes_a_large_buffer() -> TestResult {
    let mut hostile = u32::MAX.to_le_bytes().to_vec();
    hostile.extend_from_slice(&[0; HOSTILE_PADDING]);
    let mut spy = SpyRead {
        data: hostile,
        served: 0,
        largest_buffer: 0,
    };
    expect(read_recording(&mut spy, &Limits::default()), 0, Check::Length);
    assert!(spy.largest_buffer <= MAX_BODY_BYTES as usize);
    Ok(())
}


#[test]
fn terminal_escapes_are_stored_as_bytes() -> TestResult {
    let evil = b"\x1b]0;evil\x07";
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), Limits::default())?;
    push(&mut writer, Direction::Out, evil, START)?;
    close(&mut writer, "user", START)?;
    let recording = read(&out, &Limits::default())?;
    assert_eq!(recording.frames.first().map(|frame| frame.bytes.clone()), Some(evil.to_vec()));
    Ok(())
}


#[test]
fn every_prefix_of_a_payload_is_malformed() -> TestResult {
    let empty_data = FramePayload::Data {
        direction: Direction::Out,
        bytes: vec![],
    };
    let payloads = [(KIND_HEADER, head_payload()), (KIND_DATA, empty_data), (KIND_TRAILER, trailer_payload())];
    for (kind, payload) in payloads {
        let full = payload_of(&payload)?;
        assert!(parse_payload(kind, &full, 0).is_ok());
        let refused = (0..full.len()).all(|cut| parse_payload(kind, &prefix_of(&full, cut), 0).is_err());
        assert!(refused);
    }
    let whole = encode_frame(&GENESIS_HASH, 0, 0, &trailer_payload())?;
    let body: Vec<u8> = whole.iter().skip(PREFIX_LEN).copied().collect();
    assert!(parse_body(&body).is_ok());
    let fixed = usize::try_from(FIXED_BODY_BYTES)?;
    assert!((0..fixed).all(|cut| parse_body(&prefix_of(&body, cut)) == Err(Check::Malformed)));
    Ok(())
}


#[test]
fn malformed_payloads_are_named() -> TestResult {
    assert_eq!(parse_payload(KIND_UNKNOWN, &[], 0), Err(Check::Kind));
    assert_eq!(parse_payload(KIND_HEADER, &[BAD_VERSION], 0), Err(Check::Version));
    assert_eq!(parse_payload(KIND_DATA, &[DIRECTION_UNKNOWN, 1], 0), Err(Check::Malformed));
    let mut trailing = payload_of(&trailer_payload())?;
    trailing.push(0);
    assert_eq!(parse_payload(KIND_TRAILER, &trailing, 0), Err(Check::Malformed));
    let mut header_trailing = payload_of(&head_payload())?;
    header_trailing.push(0);
    assert_eq!(parse_payload(KIND_HEADER, &header_trailing, 0), Err(Check::Malformed));
    let bad_utf8 = [GOOD_VERSION, 1, 0, BYTE_FF];
    assert_eq!(parse_payload(KIND_HEADER, &bad_utf8, 0), Err(Check::Malformed));
    let too_long = [GOOD_VERSION, BYTE_FF, BYTE_FF];
    assert_eq!(parse_payload(KIND_HEADER, &too_long, 0), Err(Check::Malformed));
    Ok(())
}


#[test]
fn read_failures_name_the_frame() -> TestResult {
    let (bytes, _) = sample()?;
    let limits = Limits::default();
    for served in [SERVED_FIRST_BYTE, SERVED_PREFIX_TAIL, SERVED_BODY, bytes.len()] {
        let mut reader = FailAfter {
            data: prefix_of(&bytes, served),
            served: 0,
        };
        let result = read_recording(&mut reader, &limits);
        assert!(matches!(result, Err(RecordingError::Read { .. })), "{served}: {result:?}");
    }
    let mut late = FailAfter {
        data: bytes.clone(),
        served: 0,
    };
    let mut buffer = vec![0; bytes.len()];
    late.read_exact(&mut buffer)?;
    assert_eq!(buffer, bytes);
    Ok(())
}


#[test]
fn errors_carry_names_and_no_content() -> TestResult {
    let checks = [
        (Check::Truncated, "truncated"),
        (Check::TrailerMissing, "trailer missing"),
        (Check::TrailingData, "data after the trailer"),
        (Check::Length, "declared length out of range"),
        (Check::Full, "recording above its caps"),
        (Check::Chain, "chain broken"),
        (Check::Sequence, "sequence broken"),
        (Check::Time, "time went back"),
        (Check::Kind, "frame kind out of place"),
        (Check::Malformed, "malformed frame"),
        (Check::Version, "unknown format version"),
    ];
    for (check, name) in checks {
        assert_eq!(check.to_string(), name);
    }
    let error = RecordingError::Frame {
        frame: SEQ_SKIPPED + 1,
        check: Check::Chain,
    };
    assert_eq!(error.to_string(), "frame 3: chain broken");
    assert_eq!(Limits::default().max_frames, DEFAULT_MAX_FRAMES);
    Ok(())
}


#[test]
fn an_unknown_kind_on_a_real_frame_is_named() -> TestResult {
    let (mut bytes, _) = sample()?;
    let kind = bytes.get_mut(PREFIX_LEN).ok_or("kind")?;
    *kind = KIND_UNKNOWN;
    expect(read(&bytes, &Limits::default()), 0, Check::Kind);
    Ok(())
}


fn hostile_input_is_refused_in_bounded_memory() -> TestResult {
    let mut hostile = u32::MAX.to_le_bytes().to_vec();
    hostile.extend_from_slice(&[0; HOSTILE_PADDING]);
    expect(read(&hostile, &Limits::default()), 0, Check::Length);
    let mut out = Vec::new();
    let mut writer = new_writer(&mut out, &header(), Limits::default())?;
    (1..MEMORY_FLOOD_FRAMES).try_for_each(|_| push(&mut writer, Direction::In, b"", START))?;
    let capped = Limits {
        max_frames: MEMORY_FLOOD_CAP,
        ..Limits::default()
    };
    expect(read(&out, &capped), MEMORY_FLOOD_CAP, Check::Full);
    Ok(())
}


#[test]
fn memory_limited_child_refuses_hostile_recordings() -> TestResult {
    std::env::var(MEMORY_LIMIT_ENV).map_or(Ok(()), |_marker| hostile_input_is_refused_in_bounded_memory())
}


#[test]
fn hostile_recordings_do_not_allocate_under_a_memory_limit() -> TestResult {
    let output = std::process::Command::new("prlimit")
        .arg(MEMORY_LIMIT_BYTES)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", "memory_limited_child_refuses_hostile_recordings", "--test-threads=1"])
        .env(MEMORY_LIMIT_ENV, "1")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}
