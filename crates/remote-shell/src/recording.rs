use crate::types::{ChainHash, HASH_LEN};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{self, ErrorKind, Read, Write};
use thiserror::Error;


pub const FORMAT_VERSION: u8 = 1;


pub const MAX_FRAME_BYTES: usize = 65_536;


pub const MAX_FIELD_BYTES: usize = 256;


pub const MAX_REASON_BYTES: usize = 64;


pub const FIXED_BODY_BYTES: u32 = 49;


pub const MAX_BODY_BYTES: u32 = 65_586;


pub const PREFIX_BYTES: u64 = 4;


pub const MAX_RECORDING_BYTES_CEILING: u64 = 4_294_967_296;


pub const DEFAULT_MAX_RECORDING_BYTES: u64 = 268_435_456;


pub const DEFAULT_MAX_FRAMES: u64 = 10_000_000;


pub const MIN_FRAMES: u64 = 2;


pub const MAX_FRAMES_CEILING: u64 = 1_000_000_000;


pub const GENESIS_HASH: ChainHash = [0; HASH_LEN];


const KIND_HEADER: u8 = 0;


const KIND_DATA: u8 = 1;


const KIND_TRAILER: u8 = 2;


const DIRECTION_IN: u8 = 0;


const DIRECTION_OUT: u8 = 1;


const DIGEST_LEN: usize = HASH_LEN;


const U64_LEN: usize = 8;


const U16_LEN: usize = 2;


const LENGTH_PREFIX_TAIL: usize = 3;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_recording_bytes: u64,
    pub max_frames: u64,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_recording_bytes: DEFAULT_MAX_RECORDING_BYTES,
            max_frames: DEFAULT_MAX_FRAMES,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub session_id: String,
    pub tenant: String,
    pub requester: String,
    pub asset: String,
    pub ticket: String,
    pub opened_at: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePayload {
    Header(Header),
    Data { direction: Direction, bytes: Vec<u8> },
    Trailer { reason: String },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    pub seq: u64,
    pub at: i64,
    pub direction: Direction,
    pub bytes: Vec<u8>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trailer {
    pub seq: u64,
    pub at: i64,
    pub reason: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    pub header: Header,
    pub frames: Vec<DataFrame>,
    pub trailer: Trailer,
    pub final_hash: ChainHash,
}


/// The check a reader refused a frame on; it never carries recording content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Truncated,
    TrailerMissing,
    TrailingData,
    Length,
    Full,
    Chain,
    Sequence,
    Time,
    Kind,
    Malformed,
    Version,
}


impl Display for Check {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        let name = match self {
            Check::Truncated => "truncated",
            Check::TrailerMissing => "trailer missing",
            Check::TrailingData => "data after the trailer",
            Check::Length => "declared length out of range",
            Check::Full => "recording above its caps",
            Check::Chain => "chain broken",
            Check::Sequence => "sequence broken",
            Check::Time => "time went back",
            Check::Kind => "frame kind out of place",
            Check::Malformed => "malformed frame",
            Check::Version => "unknown format version",
        };
        formatter.write_str(name)
    }
}


#[derive(Debug, Error)]
pub enum RecordingError {
    #[error("recording write failed")]
    Write(#[source] io::Error),
    #[error("recording read failed at frame {frame}")]
    Read {
        frame: u64,
        #[source]
        source: io::Error,
    },
    #[error("recording is full")]
    Full,
    #[error("recording is closed")]
    Closed,
    #[error("frame above the frame cap")]
    FrameTooLarge,
    #[error("header or reason field too long")]
    FieldTooLong,
    #[error("recording limits out of range")]
    Limits,
    #[error("time went back")]
    TimeWentBack,
    #[error("frame {frame}: {check}")]
    Frame { frame: u64, check: Check },
}


pub struct RecordingWriter<'a> {
    pub write: &'a mut dyn Write,
    pub prev: ChainHash,
    pub next_seq: u64,
    pub last_at: i64,
    pub bytes: u64,
    pub limits: Limits,
    pub closed: bool,
}


#[derive(Debug)]
pub struct ReadState {
    pub prev: ChainHash,
    pub expected_seq: u64,
    pub last_at: i64,
    pub bytes: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub seq: u64,
    pub at: i64,
    pub payload: FramePayload,
}


#[derive(Debug, PartialEq, Eq)]
pub struct ParsedBody<'a> {
    pub kind: u8,
    pub prev: ChainHash,
    pub seq: u64,
    pub at: i64,
    pub payload: &'a [u8],
}


pub fn check_limits(limits: &Limits) -> Result<(), RecordingError> {
    let bytes_ok = limits.max_recording_bytes >= u64::from(MAX_BODY_BYTES) && limits.max_recording_bytes <= MAX_RECORDING_BYTES_CEILING;
    let frames_ok = limits.max_frames >= MIN_FRAMES && limits.max_frames <= MAX_FRAMES_CEILING;
    if bytes_ok && frames_ok {
        Ok(())
    } else {
        Err(RecordingError::Limits)
    }
}


pub fn frame_hash(frame: &[u8]) -> ChainHash {
    ChainHash::from(Sha256::digest(frame))
}


fn put_string(out: &mut Vec<u8>, text: &str, cap: usize) -> Result<(), RecordingError> {
    if text.len() > cap {
        Err(RecordingError::FieldTooLong)
    } else {
        out.extend_from_slice(&(text.len() as u16).to_le_bytes());
        out.extend_from_slice(text.as_bytes());
        Ok(())
    }
}


fn encode_payload(out: &mut Vec<u8>, payload: &FramePayload) -> Result<(), RecordingError> {
    match payload {
        FramePayload::Header(header) => {
            out.push(FORMAT_VERSION);
            put_string(out, &header.session_id, MAX_FIELD_BYTES)?;
            put_string(out, &header.tenant, MAX_FIELD_BYTES)?;
            put_string(out, &header.requester, MAX_FIELD_BYTES)?;
            put_string(out, &header.asset, MAX_FIELD_BYTES)?;
            put_string(out, &header.ticket, MAX_FIELD_BYTES)
        }
        FramePayload::Data { direction, bytes } => {
            if bytes.len() > MAX_FRAME_BYTES {
                Err(RecordingError::FrameTooLarge)
            } else {
                out.push(direction_code(*direction));
                out.extend_from_slice(bytes);
                Ok(())
            }
        }
        FramePayload::Trailer { reason } => put_string(out, reason, MAX_REASON_BYTES),
    }
}


fn direction_code(direction: Direction) -> u8 {
    match direction {
        Direction::In => DIRECTION_IN,
        Direction::Out => DIRECTION_OUT,
    }
}


fn kind_code(payload: &FramePayload) -> u8 {
    match payload {
        FramePayload::Header(_) => KIND_HEADER,
        FramePayload::Data { .. } => KIND_DATA,
        FramePayload::Trailer { .. } => KIND_TRAILER,
    }
}


/// One frame on the wire: u32 LE body length, then kind, prev hash, seq, at, payload; the frame hash covers all of it.
pub fn encode_frame(prev: &ChainHash, seq: u64, at: i64, payload: &FramePayload) -> Result<Vec<u8>, RecordingError> {
    let mut body = vec![kind_code(payload)];
    body.extend_from_slice(prev);
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&at.to_le_bytes());
    encode_payload(&mut body, payload)?;
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}


fn append_frame(writer: &mut RecordingWriter<'_>, payload: &FramePayload, at: i64) -> Result<ChainHash, RecordingError> {
    if writer.closed {
        Err(RecordingError::Closed)
    } else if at < writer.last_at {
        Err(RecordingError::TimeWentBack)
    } else {
        let frame = encode_frame(&writer.prev, writer.next_seq, at, payload)?;
        let total = writer.bytes + frame.len() as u64;
        if total > writer.limits.max_recording_bytes || writer.next_seq >= writer.limits.max_frames {
            Err(RecordingError::Full)
        } else {
            writer.write.write_all(&frame).map_err(RecordingError::Write)?;
            writer.prev = frame_hash(&frame);
            writer.next_seq += 1;
            writer.last_at = at;
            writer.bytes = total;
            Ok(writer.prev)
        }
    }
}


fn append(writer: &mut RecordingWriter<'_>, payload: &FramePayload, at: i64) -> Result<ChainHash, RecordingError> {
    let result = append_frame(writer, payload, at);
    writer.closed = writer.closed || result.is_err();
    result
}


/// Writes the header frame at once; any error means the caller must end the session (`RecordingFailed`).
pub fn new_writer<'a>(write: &'a mut dyn Write, header: &Header, limits: Limits) -> Result<RecordingWriter<'a>, RecordingError> {
    check_limits(&limits)?;
    let mut writer = RecordingWriter {
        write,
        prev: GENESIS_HASH,
        next_seq: 0,
        last_at: header.opened_at,
        bytes: 0,
        limits,
        closed: false,
    };
    append(&mut writer, &FramePayload::Header(header.clone()), header.opened_at)?;
    Ok(writer)
}


pub fn push(writer: &mut RecordingWriter<'_>, direction: Direction, bytes: &[u8], at: i64) -> Result<(), RecordingError> {
    let payload = FramePayload::Data {
        direction,
        bytes: bytes.to_vec(),
    };
    append(writer, &payload, at).map(|_hash| ())
}


/// Writes the trailer and returns the final hash, which the storage slice records in the audit.
pub fn close(writer: &mut RecordingWriter<'_>, reason: &str, at: i64) -> Result<ChainHash, RecordingError> {
    let payload = FramePayload::Trailer { reason: reason.to_string() };
    let hash = append(writer, &payload, at)?;
    writer.closed = true;
    writer.write.flush().map_err(RecordingError::Write)?;
    Ok(hash)
}


fn take(input: &[u8], count: usize) -> Result<(&[u8], &[u8]), Check> {
    input.split_at_checked(count).ok_or(Check::Malformed)
}


fn take_u8(input: &[u8]) -> Result<(u8, &[u8]), Check> {
    let (head, rest) = take(input, 1)?;
    head.first().copied().map(|value| (value, rest)).ok_or(Check::Malformed)
}


fn take_digest(input: &[u8]) -> Result<(ChainHash, &[u8]), Check> {
    let (head, rest) = take(input, DIGEST_LEN)?;
    let mut digest = GENESIS_HASH;
    digest.copy_from_slice(head);
    Ok((digest, rest))
}


fn take_u64(input: &[u8]) -> Result<(u64, &[u8]), Check> {
    let (head, rest) = take(input, U64_LEN)?;
    let mut raw = [0; U64_LEN];
    raw.copy_from_slice(head);
    Ok((u64::from_le_bytes(raw), rest))
}


fn take_u16(input: &[u8]) -> Result<(u16, &[u8]), Check> {
    let (head, rest) = take(input, U16_LEN)?;
    let mut raw = [0; U16_LEN];
    raw.copy_from_slice(head);
    Ok((u16::from_le_bytes(raw), rest))
}


fn take_string(input: &[u8], cap: usize) -> Result<(String, &[u8]), Check> {
    let (length, after_length) = take_u16(input)?;
    let length_bytes = usize::from(length);
    if length_bytes > cap {
        Err(Check::Malformed)
    } else {
        let (text, rest) = take(after_length, length_bytes)?;
        let owned = String::from_utf8(text.to_vec()).or(Err(Check::Malformed))?;
        Ok((owned, rest))
    }
}


pub fn parse_body(body: &[u8]) -> Result<ParsedBody<'_>, Check> {
    let (kind, after_kind) = take_u8(body)?;
    let (prev, after_prev) = take_digest(after_kind)?;
    let (seq, after_seq) = take_u64(after_prev)?;
    let (at_raw, payload) = take_u64(after_seq)?;
    Ok(ParsedBody {
        kind,
        prev,
        seq,
        at: i64::from_le_bytes(at_raw.to_le_bytes()),
        payload,
    })
}


fn parse_header(payload: &[u8], at: i64) -> Result<FramePayload, Check> {
    let (version, after_version) = take_u8(payload)?;
    if version == FORMAT_VERSION {
        let (session_id, after_session) = take_string(after_version, MAX_FIELD_BYTES)?;
        let (tenant, after_tenant) = take_string(after_session, MAX_FIELD_BYTES)?;
        let (requester, after_requester) = take_string(after_tenant, MAX_FIELD_BYTES)?;
        let (asset, after_asset) = take_string(after_requester, MAX_FIELD_BYTES)?;
        let (ticket, after_ticket) = take_string(after_asset, MAX_FIELD_BYTES)?;
        if after_ticket.is_empty() {
            Ok(FramePayload::Header(Header {
                session_id,
                tenant,
                requester,
                asset,
                ticket,
                opened_at: at,
            }))
        } else {
            Err(Check::Malformed)
        }
    } else {
        Err(Check::Version)
    }
}


fn parse_data(payload: &[u8]) -> Result<FramePayload, Check> {
    let (code, bytes) = take_u8(payload)?;
    match code {
        DIRECTION_IN => Ok(FramePayload::Data {
            direction: Direction::In,
            bytes: bytes.to_vec(),
        }),
        DIRECTION_OUT => Ok(FramePayload::Data {
            direction: Direction::Out,
            bytes: bytes.to_vec(),
        }),
        _ => Err(Check::Malformed),
    }
}


fn parse_trailer(payload: &[u8]) -> Result<FramePayload, Check> {
    let (reason, rest) = take_string(payload, MAX_REASON_BYTES)?;
    if rest.is_empty() {
        Ok(FramePayload::Trailer { reason })
    } else {
        Err(Check::Malformed)
    }
}


pub fn parse_payload(kind: u8, payload: &[u8], at: i64) -> Result<FramePayload, Check> {
    match kind {
        KIND_HEADER => parse_header(payload, at),
        KIND_DATA => parse_data(payload),
        KIND_TRAILER => parse_trailer(payload),
        _ => Err(Check::Kind),
    }
}


fn frame_error(frame: u64, check: Check) -> RecordingError {
    RecordingError::Frame { frame, check }
}


fn read_failure(frame: u64, error: io::Error) -> RecordingError {
    if error.kind() == ErrorKind::UnexpectedEof {
        frame_error(frame, Check::Truncated)
    } else {
        RecordingError::Read { frame, source: error }
    }
}


fn first_byte_failure(frame: u64, error: io::Error) -> RecordingError {
    if error.kind() == ErrorKind::UnexpectedEof && frame > 0 {
        frame_error(frame, Check::TrailerMissing)
    } else {
        read_failure(frame, error)
    }
}


fn read_declared_length(reader: &mut dyn Read, frame: u64) -> Result<u32, RecordingError> {
    let mut first = [0; 1];
    reader.read_exact(&mut first).map_err(|error| first_byte_failure(frame, error))?;
    let mut rest = [0; LENGTH_PREFIX_TAIL];
    reader.read_exact(&mut rest).map_err(|error| read_failure(frame, error))?;
    let [first_byte] = first;
    let [second, third, fourth] = rest;
    Ok(u32::from_le_bytes([first_byte, second, third, fourth]))
}


/// Reads one frame: every length is checked before the body buffer is sized, then chain, sequence and time.
pub fn read_raw_frame(reader: &mut dyn Read, state: &mut ReadState, limits: &Limits) -> Result<RawFrame, RecordingError> {
    let frame = state.expected_seq;
    let declared = read_declared_length(reader, frame)?;
    if !(FIXED_BODY_BYTES..=MAX_BODY_BYTES).contains(&declared) {
        Err(frame_error(frame, Check::Length))
    } else if state.bytes + PREFIX_BYTES + u64::from(declared) > limits.max_recording_bytes {
        Err(frame_error(frame, Check::Full))
    } else {
        let mut body = vec![0; declared as usize];
        reader.read_exact(&mut body).map_err(|error| read_failure(frame, error))?;
        let hash = ChainHash::from(Sha256::new().chain_update(declared.to_le_bytes()).chain_update(&body).finalize());
        let parsed = parse_body(&body).or(Err(frame_error(frame, Check::Malformed)))?;
        if parsed.prev != state.prev {
            Err(frame_error(frame, Check::Chain))
        } else if parsed.seq != frame {
            Err(frame_error(frame, Check::Sequence))
        } else if parsed.at < state.last_at {
            Err(frame_error(frame, Check::Time))
        } else {
            let payload = parse_payload(parsed.kind, parsed.payload, parsed.at).map_err(|check| frame_error(frame, check))?;
            state.prev = hash;
            state.expected_seq += 1;
            state.last_at = parsed.at;
            state.bytes += PREFIX_BYTES + u64::from(declared);
            Ok(RawFrame {
                seq: parsed.seq,
                at: parsed.at,
                payload,
            })
        }
    }
}


fn check_end(reader: &mut dyn Read, frame: u64) -> Result<(), RecordingError> {
    let mut probe = [0; 1];
    match reader.read_exact(&mut probe) {
        Ok(()) => Err(frame_error(frame, Check::TrailingData)),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(()),
        Err(error) => Err(RecordingError::Read { frame, source: error }),
    }
}


fn read_header(reader: &mut dyn Read, state: &mut ReadState, limits: &Limits) -> Result<Header, RecordingError> {
    let first = read_raw_frame(reader, state, limits)?;
    match first.payload {
        FramePayload::Header(header) => Ok(header),
        FramePayload::Data { .. } | FramePayload::Trailer { .. } => Err(frame_error(first.seq, Check::Kind)),
    }
}


/// Reads and verifies a whole recording: header first, trailer last, chain, sequence, time and every cap.
pub fn read_recording(reader: &mut dyn Read, limits: &Limits) -> Result<Recording, RecordingError> {
    check_limits(limits)?;
    let mut state = ReadState {
        prev: GENESIS_HASH,
        expected_seq: 0,
        last_at: i64::MIN,
        bytes: 0,
    };
    let header = read_header(reader, &mut state, limits)?;
    let mut frames = Vec::new();
    let mut trailer = None;
    while trailer.is_none() && state.expected_seq < limits.max_frames.min(MAX_FRAMES_CEILING) {
        let raw = read_raw_frame(reader, &mut state, limits)?;
        match raw.payload {
            FramePayload::Data { direction, bytes } => frames.push(DataFrame {
                seq: raw.seq,
                at: raw.at,
                direction,
                bytes,
            }),
            FramePayload::Trailer { reason } => {
                trailer = Some(Trailer {
                    seq: raw.seq,
                    at: raw.at,
                    reason,
                });
            }
            FramePayload::Header(_) => Err(frame_error(raw.seq, Check::Kind))?,
        }
    }
    let ended = trailer.ok_or(frame_error(state.expected_seq, Check::Full))?;
    check_end(reader, state.expected_seq)?;
    Ok(Recording {
        header,
        frames,
        trailer: ended,
        final_hash: state.prev,
    })
}
