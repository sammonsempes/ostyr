use crate::types::{SpoolLock, UpdateRunFn};
use patch_inventory::model::Limits;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;


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


pub const DEFAULT_OSQUERYI_PATH: &str = "/usr/bin/osqueryi";


pub const DEFAULT_OSQUERY_DEADLINE_SECONDS: u64 = 60;


pub const MAX_OSQUERY_DEADLINE_SECONDS: u64 = 600;


pub const DEFAULT_PRLIMIT_PATH: &str = "/usr/bin/prlimit";


pub const MIN_OSQUERY_MEMORY_BYTES: u64 = 67_108_864;


pub const DEFAULT_OSQUERY_MEMORY_BYTES: u64 = 536_870_912;


pub const MAX_OSQUERY_MEMORY_BYTES: u64 = 2_147_483_648;


pub const MIN_OSQUERY_TEMP_BYTES: u64 = 16_777_216;


pub const DEFAULT_OSQUERY_TEMP_BYTES: u64 = 134_217_728;


pub const MAX_OSQUERY_TEMP_BYTES: u64 = 1_073_741_824;


pub const DEFAULT_SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";


pub const DEFAULT_CREDENTIALS_PATH: &str = "/etc/tetragon/tetragon.conf.d/enable-process-cred";


pub const DEFAULT_NFT_PATH: &str = "/usr/sbin/nft";


pub const MAX_ENDPOINTS: usize = 8;


pub const MAX_DNS_RESOLVERS: usize = 4;


pub const DEFAULT_SENSOR_WINDOW_SECONDS: u64 = 120;


pub const DEFAULT_SENSOR_INTERVAL_SECONDS: u64 = 10;


pub const DEFAULT_MAX_RESTARTS_PER_HOUR: u64 = 6;


pub const MAX_SENSOR_WINDOW_SECONDS: u64 = 240;


pub const MAX_SENSOR_INTERVAL_SECONDS: u64 = 30;


pub const MAX_RESTARTS_PER_HOUR_CEILING: u64 = 60;


pub const MIN_UPDATE_INTERVAL_SECONDS: u64 = 300;


pub const DEFAULT_UPDATE_INTERVAL_SECONDS: u64 = 21_600;


pub const MAX_UPDATE_INTERVAL_SECONDS: u64 = 604_800;


pub const DEFAULT_UPDATE_DEADLINE_SECONDS: u64 = 120;


pub const MAX_UPDATE_DEADLINE_SECONDS: u64 = 600;


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


/// The package manager whose missing updates are listed; `none` (the default) lists nothing, the agent never guesses the family.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Manager {
    Apt,
    Dnf,
    #[default]
    None,
}


/// The live-reloaded bounds of the update inventory: the manager, seconds between runs, and the deadline of each command.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateSettings {
    pub manager: Manager,
    pub interval_seconds: u64,
    pub deadline_seconds: u64,
}


impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            manager: Manager::None,
            interval_seconds: DEFAULT_UPDATE_INTERVAL_SECONDS,
            deadline_seconds: DEFAULT_UPDATE_DEADLINE_SECONDS,
        }
    }
}


/// The live-reloaded osquery settings: the absolute `osqueryi` and `prlimit` paths (judged again before every run), the deadline, the address-space limit and the largest file (temp spill) of one query.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct OsquerySettings {
    pub path: PathBuf,
    pub prlimit_path: PathBuf,
    pub deadline_seconds: u64,
    pub max_memory_bytes: u64,
    pub max_temp_bytes: u64,
}


impl Default for OsquerySettings {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_OSQUERYI_PATH),
            prlimit_path: PathBuf::from(DEFAULT_PRLIMIT_PATH),
            deadline_seconds: DEFAULT_OSQUERY_DEADLINE_SECONDS,
            max_memory_bytes: DEFAULT_OSQUERY_MEMORY_BYTES,
            max_temp_bytes: DEFAULT_OSQUERY_TEMP_BYTES,
        }
    }
}


/// Where one query runs: `state_dir` holds the private logger directory, `trusted_uid` is the owner every checked path must have, `run` is injected.
#[derive(Clone, Debug)]
pub struct OsqueryEnv {
    pub state_dir: PathBuf,
    pub trusted_uid: u32,
    pub run: UpdateRunFn,
}


/// The rows of one query, each a column to value map, and how many rows were refused alone for breaking a bound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryRows {
    pub rows: Vec<BTreeMap<String, String>>,
    pub refused_rows: usize,
}


/// One command of the generalised bounded runner: `environment` of `None` inherits the agent's, `Some` clears it and sets exactly those variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Option<Vec<(String, String)>>,
    pub accepted_codes: Vec<i32>,
    pub max_output: u64,
}


/// Why a run listed nothing; the name is the `outcome` of the summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    TimedOut,
    TooLarge,
    Exit(Option<i32>),
    Spawn,
}


/// The facts of one run's summary line; `exit_code` is the status of a command that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SummaryFacts<'a> {
    pub run_id: u64,
    pub outcome: &'a str,
    pub count: usize,
    pub oversized: usize,
    pub truncated: usize,
    pub exit_code: Option<i32>,
    pub lists_age_seconds: Option<u64>,
    pub counter_reset: bool,
}


/// Where the update inventory reads and writes; `run` is injected, the program paths are constants of `updates.rs`.
#[derive(Clone, Debug)]
pub struct UpdateEnv {
    pub lists_dir: PathBuf,
    pub spool: PathBuf,
    pub sending: PathBuf,
    pub counter_file: PathBuf,
    pub state: Arc<StateDir>,
    pub lock: SpoolLock,
    pub tenant: String,
    pub device_id: String,
    pub line_limit: usize,
    pub max_events: usize,
    pub limits: Limits,
    pub run: UpdateRunFn,
}


pub fn default_systemctl_path() -> PathBuf {
    PathBuf::from(DEFAULT_SYSTEMCTL_PATH)
}


pub fn default_credentials_path() -> PathBuf {
    PathBuf::from(DEFAULT_CREDENTIALS_PATH)
}


pub fn default_nft_path() -> PathBuf {
    PathBuf::from(DEFAULT_NFT_PATH)
}


/// A platform or relay endpoint the isolated host may still reach: a parsed address, so no setting text reaches the ruleset, and a TCP port.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}


/// What network isolation still lets through: the endpoints, and the DNS resolvers only when named.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IsolationSettings {
    pub endpoints: Vec<Endpoint>,
    pub dns: Vec<IpAddr>,
}


/// The settings file; `settings`, `sensor` and `updates` are live-reloaded, the paths (`systemctl_path` included) are read at start.
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
    #[serde(default)]
    pub updates: UpdateSettings,
    #[serde(default)]
    pub osquery: OsquerySettings,
    #[serde(default = "default_systemctl_path")]
    pub systemctl_path: PathBuf,
    #[serde(default)]
    pub isolation: IsolationSettings,
    #[serde(default = "default_credentials_path")]
    pub credentials_path: PathBuf,
    #[serde(default = "default_nft_path")]
    pub nft_path: PathBuf,
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


/// Jiffies per CPU state from the aggregate `cpu ` line of `proc/stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}


#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}


#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountStat {
    pub mount: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
}


/// The mounts that answered, how many failed and how many paths were left out by the `MAX_MOUNTS` cap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountSurvey {
    pub mounts: Vec<MountStat>,
    pub failed: u64,
    pub omitted: u64,
}


/// One reading of the host counters; a value that could not be read is `None`, never a guess.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostSample {
    pub cpu: Option<CpuTimes>,
    pub mem_total_bytes: Option<u64>,
    pub mem_available_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
    pub load: Option<LoadAverage>,
    pub oom_kill: Option<u64>,
    pub boot_id: Option<String>,
    pub uptime_seconds: Option<f64>,
    pub survey: MountSurvey,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}


/// One accept rule of the isolation table: loopback of the named hook, IPv6 neighbour discovery, a path-MTU error of one listed flow, a destination address and port, or the tracked replies of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Loopback(&'static str),
    Neighbour,
    PathError { address: IpAddr, protocol: Protocol, port: u16 },
    Destination { address: IpAddr, protocol: Protocol, port: u16 },
    Reply { address: IpAddr, protocol: Protocol, port: u16 },
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolationStatus {
    Absent,
    Active,
}


#[derive(Debug, Deserialize)]
pub struct TableJson {
    pub family: String,
    pub name: String,
}


#[derive(Debug, Deserialize)]
pub struct ChainJson {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub hook: Option<String>,
    pub prio: Option<i64>,
    pub policy: Option<String>,
}


#[derive(Debug, Deserialize)]
pub struct RuleJson {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub expr: Vec<serde_json::Value>,
}


/// One element of the `nftables` array of `nft -j`; an element holding none of the known keys is a mismatch.
#[derive(Debug, Deserialize)]
pub struct ItemJson {
    pub table: Option<TableJson>,
    pub chain: Option<ChainJson>,
    pub rule: Option<RuleJson>,
    pub metainfo: Option<Box<serde_json::value::RawValue>>,
}


#[derive(Debug, Deserialize)]
pub struct ListingJson {
    pub nftables: Vec<Box<serde_json::value::RawValue>>,
}
