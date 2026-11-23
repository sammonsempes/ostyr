use crate::types::{EncodeFn, Runner};
use ecs_normalise::types::SeenIds;
use std::path::Path;


pub const WEVTUTIL_PATH: &str = r"C:\Windows\System32\wevtutil.exe";


#[cfg(windows)]
pub const WORKING_DIRECTORY: &str = r"C:\Windows\System32";


#[cfg(not(windows))]
pub const WORKING_DIRECTORY: &str = "/";


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


pub const HIGH_SURROGATE_FIRST: u16 = 0xD800;


pub const HIGH_SURROGATE_LAST: u16 = 0xDBFF;


pub const LOW_SURROGATE_FIRST: u16 = 0xDC00;


pub const LOW_SURROGATE_LAST: u16 = 0xDFFF;


pub const BYTE_ORDER_MARK: u16 = 0xFEFF;


pub const NONCHARACTER_FFFE: u16 = 0xFFFE;


pub const NONCHARACTER_FFFF: u16 = 0xFFFF;


pub const GUID_TEXT_BYTES: usize = 36;


pub const GUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];


pub const TIME_SHAPE: &str = "DDDD-DD-DDTDD:DD:DD.DDDDDDDZ";


pub const MONTHS_PER_YEAR: u32 = 12;


pub const HOURS_PER_DAY: u32 = 24;


pub const MINUTES_PER_HOUR: u32 = 60;


pub const SECONDS_PER_MINUTE: u32 = 60;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Flag,
    Count,
    Text,
    Time,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    pub source: &'static str,
    pub name: &'static str,
    pub kind: Kind,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenderRefusal {
    Unavailable,
    Malformed,
    Undecodable,
}


pub const FIRST_PRINTABLE_UNIT: u16 = 0x20;


pub const TAB_UNIT: u16 = 0x09;


pub const LINE_FEED_UNIT: u16 = 0x0A;


pub const CARRIAGE_RETURN_UNIT: u16 = 0x0D;


pub const REPLACEMENT: char = '\u{FFFD}';


pub const NEWEST_COUNT: u32 = 1;


pub const POLL_INTERVAL_SECONDS: u64 = 10;


pub const MAX_REPOLLS_PER_CYCLE: u32 = 4;


pub const REPLACED_LABEL: &str = "agent.utf16_replaced";


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
    Recreated,
    Valid { record_id: u64, time: String, created: Option<String> },
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    Hole,
    CursorInvalid,
    CursorAhead,
    LogRecreated,
    Utf16,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Oversized,
    Malformed,
    Forged,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Complete,
    Oversized,
    Nested,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub kind: ItemKind,
    pub text: String,
    pub size: usize,
    pub replaced: u32,
}


#[derive(Debug, Default)]
pub struct Splitter {
    pub inside: bool,
    pub item: String,
    pub size: usize,
    pub start_match: usize,
    pub end_match: usize,
    pub nested: bool,
    pub replaced: u32,
}


#[derive(Debug, Default)]
pub struct Utf16State {
    pub carry: Option<u8>,
    pub high: Option<u16>,
    pub started: bool,
    pub bad_order: bool,
}


#[derive(Debug, Default)]
pub struct Stream {
    pub decoder: Utf16State,
    pub splitter: Splitter,
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
    pub forged: u64,
    pub utf16: u64,
    pub utf16_replaced: u64,
    pub cursor_ahead: u64,
    pub cursor_invalid: u64,
    pub channel_absent: u64,
    pub output_capped: u64,
    pub deadline: u64,
    pub batch_halved: u64,
    pub query_failed: u64,
    pub log_recreated: u64,
    pub creation_unknown: u64,
    pub spool_full: u64,
    pub full_batches: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelState {
    pub batch: u32,
    pub absent_logged: bool,
    pub paused_polls: u32,
}


impl Default for ChannelState {
    fn default() -> Self {
        Self {
            batch: MAX_EVENTS_PER_POLL,
            absent_logged: false,
            paused_polls: 0,
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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Newest {
    Id(u64),
    Empty,
    Absent,
    Failed,
}


#[derive(Debug)]
pub struct First {
    pub end: RunEnd,
    pub info: Option<SystemInfo>,
    pub torn: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Item(SystemInfo),
    Empty,
    Failed,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Intact,
    Recreated,
    Failed,
}


#[derive(Debug)]
pub struct Plan {
    pub after: u64,
    pub cursor: Option<u64>,
    pub lines: Vec<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgedAt {
    pub first: Option<u64>,
    pub breaking: Option<u64>,
    pub count_only: bool,
}


#[derive(Debug)]
pub struct Pending {
    pub id: u64,
    pub replaced: u32,
    pub info: SystemInfo,
    pub size: usize,
    pub outcome: Outcome,
}


#[derive(Debug, Default)]
pub struct Batch {
    pub lead: Vec<String>,
    pub pending: Vec<Pending>,
    pub forged: Option<ForgedAt>,
    pub seen: u64,
    pub after: u64,
    pub newest: u64,
    pub limit: u32,
    pub cursor: Option<u64>,
    pub totals: PollTotals,
}


#[derive(Debug, Default)]
pub struct Settled {
    pub lines: Vec<String>,
    pub last: Option<(u64, String)>,
    pub refetch: bool,
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
    pub max_spool_bytes: u64,
    pub seen: &'a mut SeenIds,
}
