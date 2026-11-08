use crate::error::ParseError;
use crate::types::{Millis, SourceMap};
use std::collections::BTreeSet;
use std::net::IpAddr;
use thiserror::Error;


pub const MAX_MESSAGE_BYTES: usize = 2048;


pub const MAX_HOST_BYTES: usize = 255;


pub const MAX_APP_BYTES: usize = 48;


pub const MAX_SD_ELEMENTS: usize = 8;


pub const MAX_SD_PARAMS: usize = 16;


pub const MAX_SD_STRING_BYTES: usize = 256;


pub const MILLI_TOKENS: u64 = 1000;


pub const PERCENT: u64 = 100;


pub const MAX_SHARE_PERCENT: u64 = 99;


pub const DEFAULT_UNKNOWN_SHARE_PERCENT: u64 = 20;


pub const FACILITY_WEIGHT: u8 = 8;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketLimits {
    pub rate_per_second: u64,
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
    pub milli_tokens: u64,
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
    pub(crate) source_limits: BucketLimits,
    pub(crate) unknown_limits: BucketLimits,
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
