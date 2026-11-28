use crate::error::ConnectorError;
use crate::manifest::valid_name;
use serde::Deserialize;
use serde_json::value::RawValue;


pub const MAX_REPLY_BYTES: usize = 1_048_576;


pub const MAX_REPLY_ELEMENTS: usize = 4_096;


pub const MAX_REPLY_DEPTH: usize = 32;


pub const MAX_REPLY_STRING_BYTES: usize = 65_536;


pub const UNICODE_DIGITS: usize = 4;


pub const HEX_RADIX: u32 = 16;


pub const SURROGATE_FIRST: u32 = 0xD800;


pub const SURROGATE_LAST: u32 = 0xDFFF;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Error,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawReply {
    pub status: Status,
    pub result: Option<Box<RawValue>>,
    pub error: Option<String>,
}


/// The verified reply: a result kept as raw JSON text, or a code from the fixed name grammar.
#[derive(Debug)]
pub enum Reply {
    Success { result: Option<Box<RawValue>> },
    Failure { code: String },
}


/// What the wire pre-scan has seen so far.
#[derive(Debug, Clone, Copy, Default)]
pub struct Scan {
    pub in_string: bool,
    pub escaped: bool,
    pub depth: usize,
    pub elements: usize,
    pub string_bytes: usize,
    pub token_bytes: usize,
    pub hex_remaining: usize,
    pub code: u32,
    pub bad_escape: bool,
}


fn bound(name: &'static str) -> ConnectorError {
    ConnectorError::ReplyBound { bound: name }
}


pub fn check_scan(state: Scan) -> Result<Scan, ConnectorError> {
    (!state.bad_escape).then_some(()).ok_or(bound("NUL or surrogate escape"))?;
    (state.token_bytes <= MAX_REPLY_STRING_BYTES)
        .then_some(())
        .ok_or(bound("number length"))?;
    (state.depth <= MAX_REPLY_DEPTH).then_some(()).ok_or(bound("nesting depth"))?;
    (state.elements <= MAX_REPLY_ELEMENTS).then_some(()).ok_or(bound("elements"))?;
    (state.string_bytes <= MAX_REPLY_STRING_BYTES)
        .then_some(state)
        .ok_or(bound("string length"))
}


/// One hex digit of a `\u` escape; a NUL or a surrogate (lone or paired) is flagged when the fourth digit arrives.
pub fn step_hex(state: Scan, byte: u8) -> Scan {
    let code = char::from(byte)
        .to_digit(HEX_RADIX)
        .map_or(state.code, |digit| state.code * HEX_RADIX + digit);
    let hex_remaining = state.hex_remaining - 1;
    let surrogate = (SURROGATE_FIRST..=SURROGATE_LAST).contains(&code);
    Scan {
        hex_remaining,
        code,
        string_bytes: state.string_bytes + 1,
        bad_escape: hex_remaining == 0 && (code == 0 || surrogate),
        ..state
    }
}


/// One byte inside a string: the escape flag, the four hex digits of a `\u` escape, the end of the string, or one more counted byte.
pub fn step_in_string(state: Scan, byte: u8) -> Scan {
    match (state.escaped, byte) {
        (false, _) if state.hex_remaining > 0 => step_hex(state, byte),
        (true, b'u') => Scan {
            escaped: false,
            hex_remaining: UNICODE_DIGITS,
            code: 0,
            string_bytes: state.string_bytes + 1,
            ..state
        },
        (true, _) => Scan {
            escaped: false,
            string_bytes: state.string_bytes + 1,
            ..state
        },
        (false, b'\\') => Scan {
            escaped: true,
            string_bytes: state.string_bytes + 1,
            ..state
        },
        (false, b'"') => Scan {
            in_string: false,
            string_bytes: 0,
            ..state
        },
        (false, _) => Scan {
            string_bytes: state.string_bytes + 1,
            ..state
        },
    }
}


/// One byte outside a string: every opener and every comma is one more element, a closer leaves a level.
pub fn step_outside(state: Scan, byte: u8) -> Scan {
    let token_bytes = if matches!(byte, b'"' | b'{' | b'[' | b'}' | b']' | b',' | b':' | b' ' | b'\t' | b'\n' | b'\r') {
        0
    } else {
        state.token_bytes + 1
    };
    match byte {
        b'"' => Scan {
            in_string: true,
            token_bytes,
            ..state
        },
        b'{' | b'[' => Scan {
            depth: state.depth + 1,
            elements: state.elements + 1,
            token_bytes,
            ..state
        },
        b'}' | b']' => Scan {
            depth: state.depth.saturating_sub(1),
            token_bytes,
            ..state
        },
        b',' => Scan {
            elements: state.elements + 1,
            token_bytes,
            ..state
        },
        _ => Scan { token_bytes, ..state },
    }
}


pub fn step(state: Scan, byte: u8) -> Result<Scan, ConnectorError> {
    check_scan(if state.in_string {
        step_in_string(state, byte)
    } else {
        step_outside(state, byte)
    })
}


/// A pre-scan of the bytes before any value is built: depth, elements at every level and string length are bounded, no serde error exists to keep.
pub fn scan_reply(bytes: &[u8]) -> Result<(), ConnectorError> {
    bytes.iter().try_fold(Scan::default(), |state, byte| step(state, *byte)).map(|_| ())
}


pub fn raw_reply(bytes: &[u8]) -> Result<RawReply, ConnectorError> {
    serde_json::from_slice(bytes).map_err(|_| ConnectorError::MalformedReply)
}


/// The reply grammar: `{"status": "ok", "result": <value>}` or `{"status": "error", "error": <name>}`; a bound or a wrong shape refuses the whole reply.
pub fn parse_reply(bytes: &[u8]) -> Result<Reply, ConnectorError> {
    (bytes.len() <= MAX_REPLY_BYTES)
        .then_some(())
        .ok_or(ConnectorError::ReplyTooLarge { max: MAX_REPLY_BYTES })?;
    scan_reply(bytes)?;
    let raw = raw_reply(bytes)?;
    match (raw.status, raw.result, raw.error) {
        (Status::Ok, result, None) => Ok(Reply::Success { result }),
        (Status::Error, None, Some(code)) if valid_name(&code) => Ok(Reply::Failure { code }),
        _ => Err(ConnectorError::MalformedReply),
    }
}
