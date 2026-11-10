use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;


pub const SETTINGS_SECTION: &str = "agent_linux";


pub const LINUX_MODULE: &str = "agent_linux";


pub const DEFAULT_POLL_MILLIS: u64 = 500;


pub const DEFAULT_MAX_LINE_BYTES: u64 = ecs_normalise::stream::MAX_LINE_BYTES;


pub const DEFAULT_MAX_SPOOL_BYTES: u64 = 67_108_864;


pub const DEFAULT_MAX_LINES_PER_POLL: u64 = 10_000;


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


/// The settings file; only `settings` is live-reloaded, the paths are read at start.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxFile {
    pub agent_file: PathBuf,
    pub export_path: PathBuf,
    pub cursor_file: PathBuf,
    pub audit_file: PathBuf,
    #[serde(default)]
    pub settings: SourceSettings,
}


/// Where the reader is: the identity of the export file (device and inode) and the offset of the first unread byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub dev: u64,
    pub ino: u64,
    pub offset: u64,
}


/// The followed export file: its persisted cursor and the handle kept open, so a rotated file is drained before the new one is opened.
#[derive(Debug, Default)]
pub struct Follower {
    pub cursor: Cursor,
    pub current: Option<File>,
}


#[derive(Clone, Debug)]
pub struct Paths {
    pub export: PathBuf,
    pub cursor_file: PathBuf,
    pub spool: PathBuf,
    pub sending: PathBuf,
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
