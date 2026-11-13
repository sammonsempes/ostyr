use crate::types::{DirHandle, SegmentList};
use std::fs::File;


pub const FRAME_HEADER_BYTES: usize = 17;


pub const MAX_PAYLOAD_BYTES: usize = 4096;


pub const MAX_FRAME_BYTES: u64 = (FRAME_HEADER_BYTES + MAX_PAYLOAD_BYTES) as u64;


pub const MAX_SEGMENT_FILES: usize = 4096;


pub const MAX_SEGMENTS_IN_TOTAL: u64 = 2048;


pub const MAX_DIRECTORY_ENTRIES: usize = 8192;


pub const MAX_SEGMENT_BYTES: u64 = 268_435_456;


pub const SEGMENT_NAME_DIGITS: usize = 20;


pub const SEGMENT_SUFFIX: &str = ".seg";


pub const GROUP_OR_OTHER_WRITE: u32 = 0o022;


pub const MIN_SEGMENTS_IN_TOTAL: u64 = 2;


pub const LOW_WATER_DIVISOR: u64 = 2;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Low,
    High,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub priority: Priority,
    pub sequence: u64,
    pub payload: Vec<u8>,
}


#[derive(Debug, PartialEq, Eq)]
pub enum FrameRead {
    End,
    Torn,
    Frame(Record, u64),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolConfig {
    pub segment_max_bytes: u64,
    pub total_max_bytes: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub first_sequence: u64,
    pub bytes: u64,
    pub low_records: u64,
    pub high_records: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryFacts {
    pub is_directory: bool,
    pub owner: u32,
    pub mode: u32,
    pub expected_owner: u32,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolStats {
    pub dropped_low: u64,
    pub dropped_high: u64,
    pub truncated_tails: u64,
    pub unlink_failures: u64,
    pub missing_segments: u64,
    pub saturated: bool,
    pub total_bytes: u64,
    pub next_sequence: u64,
    pub segments: usize,
}


#[derive(Debug)]
pub struct Spool {
    pub(crate) dir: DirHandle,
    pub(crate) config: SpoolConfig,
    pub(crate) segments: SegmentList,
    pub(crate) active: File,
    pub(crate) next_sequence: u64,
    pub(crate) total_bytes: u64,
    pub(crate) dropped_low: u64,
    pub(crate) dropped_high: u64,
    pub(crate) truncated_tails: u64,
    pub(crate) unlink_failures: u64,
    pub(crate) missing_segments: u64,
    pub(crate) saturated: bool,
    pub epoch: String,
}
