use crate::error::ConnectorError;
use crate::manifest::valid_name;
use serde::Deserialize;
use serde_json::value::RawValue;


pub const MAX_REPLY_BYTES: usize = 1_048_576;


pub const MAX_REPLY_ELEMENTS: usize = 4_096;


pub const MAX_REPLY_DEPTH: usize = 32;


pub const MAX_REPLY_STRING_BYTES: usize = 65_536;


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
}


fn bound(name: &'static str) -> ConnectorError {
    ConnectorError::ReplyBound { bound: name }
}


pub fn check_scan(state: Scan) -> Result<Scan, ConnectorError> {
    (state.depth <= MAX_REPLY_DEPTH).then_some(()).ok_or(bound("nesting depth"))?;
    (state.elements <= MAX_REPLY_ELEMENTS).then_some(()).ok_or(bound("elements"))?;
    (state.string_bytes <= MAX_REPLY_STRING_BYTES)
        .then_some(state)
        .ok_or(bound("string length"))
}


/// One byte inside a string: the escape flag, the end of the string, or one more counted byte.
pub fn step_in_string(state: Scan, byte: u8) -> Scan {
    match (state.escaped, byte) {
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
    match byte {
        b'"' => Scan { in_string: true, ..state },
        b'{' | b'[' => Scan {
            depth: state.depth + 1,
            elements: state.elements + 1,
            ..state
        },
        b'}' | b']' => Scan {
            depth: state.depth.saturating_sub(1),
            ..state
        },
        b',' => Scan {
            elements: state.elements + 1,
            ..state
        },
        _ => state,
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
