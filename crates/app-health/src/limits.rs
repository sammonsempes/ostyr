//! Default caps and threshold bounds.

pub const DEFAULT_MAX_BYTES: u64 = 4096;


pub const MAX_OFFSET_SECONDS_LIMIT: f64 = 3600.0;


pub const MIN_STRATUM_LIMIT: u32 = 1;


pub const MAX_STRATUM_LIMIT: u32 = 15;


pub const MIN_OFFSET_SECONDS_EXCLUSIVE: f64 = 0.0;


pub const MAX_UNITS: usize = 512;


pub const MAX_UNIT_NAME_CHARS: usize = 255;


pub const MAX_EXPECTATIONS_BYTES: usize = 1_048_576;


pub const DEFAULT_FLAP_RESTARTS: u32 = 3;


pub const MAX_FLAP_RESTARTS: u32 = 100;


pub const MAX_SUB_STATE_CHARS: usize = 64;


pub const MAX_JOURNAL_BYTES: u64 = 4_194_304;


pub const MAX_EXCERPT_LINES: usize = 200;


pub const MIN_LINE_BYTES: usize = 64;
