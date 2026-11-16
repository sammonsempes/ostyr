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


pub const MIN_MAX_AGE_SECONDS: u64 = 60;


pub const MAX_MAX_AGE_SECONDS: u64 = 31_536_000;


pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;


pub const MAX_LINE_BYTES: usize = 65_536;


pub const MAX_DATABASES: usize = 512;


pub const MAX_ACTIVITY_ROWS: usize = 1000;


pub const MAX_REPLICATION_ROWS: usize = 256;


pub const MAX_SETTINGS_ROWS: usize = 1;


pub const MIN_SLOW_QUERY_MS: u64 = 100;


pub const MAX_DB_MS: u64 = 86_400_000;


pub const MAX_MIN_REPLICAS: u32 = 16;


pub const MAX_RATIO_LIMIT: f64 = 1.0;


pub const MIN_RATIO_EXCLUSIVE: f64 = 0.0;


pub const MAX_APPLICATION_NAME_CHARS: usize = 64;
