use core_export::ecs::EcsEvent;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;


const MIB: u64 = 1_048_576;


const DEFAULT_MAX_FILE_BYTES: u64 = 32 * MIB;


const DEFAULT_MAX_FILES_PER_TICK: usize = 1_000;


const DEFAULT_MAX_LINES_PER_TICK: usize = 100_000;


const DEFAULT_MAX_LINE_BYTES: usize = 65_536;


const DEFAULT_MAX_SIGHTINGS_PER_FILE: usize = 16;


const DEFAULT_MAX_RULE_BYTES: u64 = MIB;


const DEFAULT_MAX_RULE_FILES: usize = 1_000;


const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 10;


const DEFAULT_COMPILE_TIMEOUT_SECS: u64 = 60;


const DEFAULT_MAX_OUTPUT_BYTES: usize = 65_536;


/// Bounds of one rule load and of one scan tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_files_per_tick: usize,
    pub max_lines_per_tick: usize,
    pub max_line_bytes: usize,
    pub max_sightings_per_file: usize,
    pub max_rule_bytes: u64,
    pub max_rule_files: usize,
    pub scan_timeout: Duration,
    pub compile_timeout: Duration,
    pub max_output_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_files_per_tick: DEFAULT_MAX_FILES_PER_TICK,
            max_lines_per_tick: DEFAULT_MAX_LINES_PER_TICK,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_sightings_per_file: DEFAULT_MAX_SIGHTINGS_PER_FILE,
            max_rule_bytes: DEFAULT_MAX_RULE_BYTES,
            max_rule_files: DEFAULT_MAX_RULE_FILES,
            scan_timeout: Duration::from_secs(DEFAULT_SCAN_TIMEOUT_SECS),
            compile_timeout: Duration::from_secs(DEFAULT_COMPILE_TIMEOUT_SECS),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}


/// The `yr` program (absolute path from the settings) and the private directory the compiled rules and the scanned copies live under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Yr {
    pub program: PathBuf,
    pub work_dir: PathBuf,
}


/// A stored file named by an EVE `fileinfo` event; the hash is checked as 64 lowercase hex before it names a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub sha256: String,
    pub src_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
}


/// What opening and reading one stored file gave; `Content` never exceeds `max_file_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    Content(Vec<u8>),
    TooLarge,
    Refused,
    Missing,
}


/// What scanning one file gave; `Failed` covers every output `yr` should not produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scanned {
    Names(Vec<String>),
    TimedOut,
    OutputCut,
    Failed,
}


/// Counters of one tick; no file content ever reaches them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickCounts {
    pub lines: u64,
    pub malformed: u64,
    pub scanned: u64,
    pub matched: u64,
    pub too_large: u64,
    pub refused: u64,
    pub timed_out: u64,
    pub output_cut: u64,
    pub missing: u64,
    pub failed: u64,
    pub deferred: u64,
    pub sightings_omitted: u64,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickOutcome {
    pub events: Vec<EcsEvent>,
    pub counts: TickCounts,
}
