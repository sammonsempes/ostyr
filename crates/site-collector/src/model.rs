use crate::error::ParseError;
use crate::types::{Millis, SourceMap};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;


pub const MAX_MESSAGE_BYTES: usize = 2048;


pub const MAX_HOST_BYTES: usize = 255;


pub const MAX_APP_BYTES: usize = 48;


pub const MAX_SD_ELEMENTS: usize = 8;


pub const MAX_SD_PARAMS: usize = 16;


pub const MAX_SD_STRING_BYTES: usize = 256;


pub const MILLIS_PER_SECOND: u64 = 1000;


pub const PERCENT: u64 = 100;


pub const UNITS_PER_TOKEN: u64 = MILLIS_PER_SECOND * PERCENT;


pub const MAX_SHARE_PERCENT: u64 = 99;


pub const MAX_UNKNOWN_SHARE_PERCENT: u64 = 50;


pub const DEFAULT_UNKNOWN_SHARE_PERCENT: u64 = 20;


pub const FACILITY_WEIGHT: u8 = 8;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketLimits {
    pub rate_per_second: u64,
    pub burst: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaledLimits {
    pub rate_per_ms: u64,
    pub burst: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    pub global: BucketLimits,
    pub source_share_percent: u64,
    pub unknown_share_percent: u64,
    pub sources: BTreeSet<IpAddr>,
    pub drop_unknown: bool,
    pub max_sources: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    pub units: u64,
    pub updated_ms: Millis,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceCounters {
    pub accepted: u64,
    pub unknown_seen: u64,
    pub dropped_unknown: u64,
    pub dropped_size: u64,
    pub dropped_rate: u64,
    pub parse_errors: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceState {
    pub bucket: Bucket,
    pub last_seen_ms: Millis,
    pub counters: SourceCounters,
}


#[derive(Debug, Clone)]
pub struct Collector {
    pub(crate) config: CollectorConfig,
    pub(crate) global_limits: ScaledLimits,
    pub(crate) source_limits: ScaledLimits,
    pub(crate) unknown_limits: ScaledLimits,
    pub(crate) global: Bucket,
    pub(crate) unknown: Bucket,
    pub(crate) sources: SourceMap,
    pub(crate) untracked_dropped: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DropReason {
    #[error("the source is not declared")]
    UnknownSource,
    #[error("the message exceeds the size cap")]
    TooLarge,
    #[error("the source exceeded its rate share")]
    SourceRate,
    #[error("undeclared sources together exceeded their combined rate")]
    UnknownRate,
    #[error("the collector exceeded its global rate")]
    GlobalRate,
    #[error("too many distinct sources are tracked")]
    SourceTableFull,
    #[error("the trap datagram exceeds the size cap")]
    TrapTooLarge,
    #[error("the trap datagram is malformed")]
    TrapMalformed,
    #[error("the SNMP message is not a v1 or v2c trap or inform")]
    TrapUnsupported,
    #[error("the flow datagram exceeds the size cap")]
    FlowTooLarge,
    #[error("the flow datagram is malformed")]
    FlowMalformed,
    #[error("the flow datagram is not NetFlow version 5")]
    FlowUnsupported,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdElement {
    pub id: String,
    pub params: Vec<(String, String)>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogRecord {
    pub priority: u8,
    pub timestamp: Option<i64>,
    pub host: Option<String>,
    pub app: Option<String>,
    pub message: String,
    pub structured_data: Vec<SdElement>,
}


#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted(SyslogRecord),
    Dropped(DropReason),
    Malformed(ParseError),
}


pub const MAX_TRAP_BYTES: usize = 1472;


pub const MAX_OID_ARCS: usize = 128;


pub const DEFAULT_MAX_VARBINDS: usize = 32;


pub const MAX_VARBINDS_CEILING: usize = 64;


pub const DEFAULT_MAX_VALUE_CHARS: usize = 256;


pub const MAX_VALUE_CHARS_CEILING: usize = 1024;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapLimits {
    pub max_varbinds: usize,
    pub max_value_chars: usize,
}


impl Default for TrapLimits {
    fn default() -> Self {
        Self {
            max_varbinds: DEFAULT_MAX_VARBINDS,
            max_value_chars: DEFAULT_MAX_VALUE_CHARS,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapVersion {
    V1,
    V2c,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapKind {
    TrapV1,
    TrapV2,
    Inform,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapVarbind {
    pub oid: String,
    pub value: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapRecord {
    pub version: TrapVersion,
    pub kind: TrapKind,
    pub trap_oid: String,
    pub agent_address: Option<Ipv4Addr>,
    pub uptime_ticks: u32,
    pub varbinds: Vec<TrapVarbind>,
    pub varbinds_omitted: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TrapDrop {
    #[error("the trap datagram exceeds the size cap")]
    TooLarge,
    #[error("the trap datagram is malformed")]
    Malformed,
    #[error("the SNMP message is not a v1 or v2c trap or inform")]
    Unsupported,
}


impl From<TrapDrop> for DropReason {
    fn from(trap_drop: TrapDrop) -> Self {
        match trap_drop {
            TrapDrop::TooLarge => Self::TrapTooLarge,
            TrapDrop::Malformed => Self::TrapMalformed,
            TrapDrop::Unsupported => Self::TrapUnsupported,
        }
    }
}
