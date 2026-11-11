use crate::types::SpoolLock;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;


pub const SETTINGS_SECTION: &str = "agent_linux";


pub const LINUX_MODULE: &str = "agent_linux";


pub const DEFAULT_POLL_MILLIS: u64 = 500;


pub const DEFAULT_MAX_LINE_BYTES: u64 = ecs_normalise::stream::MAX_LINE_BYTES;


pub const MAX_POLL_MILLIS: u64 = 3_600_000;


pub const MAX_LINE_BYTES_CEILING: u64 = agent_channel::model::MAX_MESSAGE_BYTES_LIMIT as u64;


pub const MAX_SPOOL_BYTES_CEILING: u64 = 268_435_456;


pub const MAX_LINES_PER_POLL_CEILING: u64 = 1_000_000;


pub const DEFAULT_MAX_SPOOL_BYTES: u64 = 67_108_864;


pub const DEFAULT_MAX_LINES_PER_POLL: u64 = 10_000;


pub const DEFAULT_SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";


pub const DEFAULT_SENSOR_WINDOW_SECONDS: u64 = 120;


pub const DEFAULT_SENSOR_INTERVAL_SECONDS: u64 = 10;


pub const DEFAULT_MAX_RESTARTS_PER_HOUR: u64 = 6;


pub const MAX_SENSOR_WINDOW_SECONDS: u64 = 240;


pub const MAX_SENSOR_INTERVAL_SECONDS: u64 = 30;


pub const MAX_RESTARTS_PER_HOUR_CEILING: u64 = 60;


/// Upper bound of the polls and agent runs of one process; the cap exists because the rules forbid an unbounded loop.
pub const MAX_POLLS: u64 = u64::MAX;


/// The bounds of the source: the part of the file applied by a reload.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct SourceSettings {
    pub poll_millis: u64,
    pub max_line_bytes: u64,
    pub max_spool_bytes: u64,
    pub max_lines_per_poll: u64,
}


impl Default for SourceSettings {
    fn default() -> Self {
        Self {
            poll_millis: DEFAULT_POLL_MILLIS,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_spool_bytes: DEFAULT_MAX_SPOOL_BYTES,
            max_lines_per_poll: DEFAULT_MAX_LINES_PER_POLL,
        }
    }
}


/// The bounds of the sensor supervisor: window of no export progress, seconds between checks, restart cap per hour (zero never restarts).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct SensorSettings {
    pub window_seconds: u64,
    pub interval_seconds: u64,
    pub max_restarts_per_hour: u64,
}


impl Default for SensorSettings {
    fn default() -> Self {
        Self {
            window_seconds: DEFAULT_SENSOR_WINDOW_SECONDS,
            interval_seconds: DEFAULT_SENSOR_INTERVAL_SECONDS,
            max_restarts_per_hour: DEFAULT_MAX_RESTARTS_PER_HOUR,
        }
    }
}


pub fn default_systemctl_path() -> PathBuf {
    PathBuf::from(DEFAULT_SYSTEMCTL_PATH)
}


/// The settings file; `settings` and `sensor` are live-reloaded, the paths (`systemctl_path` included) are read at start.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxFile {
    pub agent_file: PathBuf,
    pub export_path: PathBuf,
    pub cursor_file: PathBuf,
    pub audit_file: PathBuf,
    #[serde(default)]
    pub settings: SourceSettings,
    #[serde(default)]
    pub sensor: SensorSettings,
    #[serde(default = "default_systemctl_path")]
    pub systemctl_path: PathBuf,
}


/// Where the reader is: file identity, offset of the first unread byte, and whether that offset is inside a skipped overlong line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub dev: u64,
    pub ino: u64,
    pub offset: u64,
    pub skipping: bool,
}


/// The followed export file: its persisted cursor and the handle kept open, so a rotated file is drained before the new one is opened.
#[derive(Debug, Default)]
pub struct Follower {
    pub cursor: Cursor,
    pub current: Option<File>,
    pub notes: Notes,
}


/// The state directory held open: the cursor and its temporary file are opened and renamed relative to this handle, never through the path.
#[derive(Debug)]
pub struct StateDir {
    pub handle: File,
}


/// Consecutive polls spent in each logged state (zero when not in it), so a state is logged on entry and exit only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Notes {
    pub full_polls: u64,
    pub unusable_polls: u64,
}


#[derive(Clone, Debug)]
pub struct Paths {
    pub export: PathBuf,
    pub cursor_file: PathBuf,
    pub spool: PathBuf,
    pub sending: PathBuf,
    pub lock: SpoolLock,
}


#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stop {
    #[default]
    Running,
    Eof,
    Full,
    Partial,
    Capped,
}


/// What one poll did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub spooled: u64,
    pub malformed: u64,
    pub unknown: u64,
    pub oversized: u64,
    pub rotated: bool,
    pub truncated: bool,
    pub missing: bool,
    pub stop: Stop,
}


#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub polls: u64,
    pub spooled: u64,
    pub malformed: u64,
    pub unknown: u64,
    pub oversized: u64,
    pub rotations: u64,
    pub failures: u64,
    pub agent_runs: u64,
    pub waiting: bool,
}
