use crate::error::PollError;
use crate::types::{EncodeFn, Runner};
use ecs_normalise::types::SeenIds;
use std::path::Path;


pub const WEVTUTIL_PATH: &str = r"C:\Windows\System32\wevtutil.exe";


pub const MAX_EVENTS_PER_POLL: u32 = 500;


pub const MAX_ITEM_BYTES: usize = 1_048_576;


pub const MAX_OUTPUT_BYTES: usize = 8_388_608;


pub const MAX_READ_ROUNDS: usize = MAX_OUTPUT_BYTES + 1;


pub const QUERY_DEADLINE_SECONDS: u64 = 30;


pub const MAX_SYSTEM_BYTES: usize = 4_096;


pub const MAX_CURSOR_BYTES: u64 = 128;


pub const MAX_TIME_BYTES: usize = 40;


pub const CHANNEL_NOT_FOUND_EXIT: i32 = 15007;


pub const MAX_RECORD_ID: u64 = u64::MAX >> 1;


pub const MAX_ID_DIGITS: usize = 20;


pub const MAX_EVENT_ID_DIGITS: usize = 5;


pub const DATA_CUT_BYTES: usize = 8_000;


pub const ENTITY_LOOKBACK: usize = 12;


pub const READ_CHUNK_BYTES: usize = 65_536;


pub const CHANNEL_DEPTH: usize = 4;


pub const LOCK_ATTEMPTS: u32 = 3_000;


pub const UNKNOWN_SYSMON_DATASET: &str = "sysmon.unknown";


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Sysmon,
    Security,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    pub name: &'static str,
    pub cursor_file: &'static str,
    pub source: Source,
}


pub const SYSMON: Channel = Channel {
    name: "Microsoft-Windows-Sysmon/Operational",
    cursor_file: "sysmon.cursor",
    source: Source::Sysmon,
};


pub const SECURITY: Channel = Channel {
    name: "Security",
    cursor_file: "security.cursor",
    source: Source::Security,
};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    pub max_bytes: usize,
    pub deadline_seconds: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEnd {
    Done,
    Capped,
    Deadline,
    Failed(Option<i32>),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorState {
    Missing,
    Invalid,
    Valid { record_id: u64, time: String },
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    Hole,
    CursorInvalid,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Oversized,
    Malformed,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Complete(Vec<u8>),
    Oversized { head: Vec<u8>, size: usize },
    Nested { head: Vec<u8>, size: usize },
}


#[derive(Debug, Default)]
pub struct Splitter {
    pub inside: bool,
    pub item: Vec<u8>,
    pub size: usize,
    pub start_match: usize,
    pub end_match: usize,
    pub nested: bool,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemInfo {
    pub record_id: Option<u64>,
    pub event_id: Option<u32>,
    pub time: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PollTotals {
    pub spooled: u64,
    pub unknown: u64,
    pub malformed: u64,
    pub oversized: u64,
    pub holes: u64,
    pub cursor_invalid: u64,
    pub channel_absent: u64,
    pub output_capped: u64,
    pub deadline: u64,
    pub batch_halved: u64,
    pub query_failed: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelState {
    pub batch: u32,
    pub absent_logged: bool,
}


impl Default for ChannelState {
    fn default() -> Self {
        Self {
            batch: MAX_EVENTS_PER_POLL,
            absent_logged: false,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drained {
    Eof,
    Capped,
    Deadline,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Line(String),
    UnknownLine(String),
    Skipped,
    Refused(Refusal),
}


#[derive(Debug)]
pub struct Plan {
    pub after: u64,
    pub prev: Option<u64>,
    pub lines: Vec<String>,
    pub totals: PollTotals,
}


#[derive(Debug, Default)]
pub struct Batch {
    pub lines: Vec<String>,
    pub prev: Option<u64>,
    pub last: Option<(u64, String)>,
    pub handled: u64,
    pub totals: PollTotals,
    pub fault: Option<PollError>,
}


#[derive(Clone, Copy)]
pub struct ItemContext<'a> {
    pub channel: &'a Channel,
    pub encode: EncodeFn,
    pub line_limit: usize,
}


pub struct PollEnv<'a> {
    pub run: Runner<'a>,
    pub encode: EncodeFn,
    pub program: &'a str,
    pub state_dir: &'a Path,
    pub spool: &'a Path,
    pub line_limit: usize,
    pub lock_attempts: u32,
    pub max_output_bytes: usize,
    pub deadline_seconds: u64,
    pub seen: &'a mut SeenIds,
}
