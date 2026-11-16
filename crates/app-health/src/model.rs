//! Data types.

use crate::limits::DEFAULT_FLAP_RESTARTS;
use serde::Deserialize;


#[derive(Debug, Clone, PartialEq)]
pub struct Tracking {
    pub reference_id: String,
    pub reference_name: Option<String>,
    pub stratum: Option<u32>,
    pub system_time_offset: Option<f64>,
    pub last_offset: Option<f64>,
    pub rms_offset: Option<f64>,
    pub frequency: Option<f64>,
    pub residual_frequency: Option<f64>,
    pub skew: Option<f64>,
    pub root_delay: Option<f64>,
    pub root_dispersion: Option<f64>,
    pub update_interval: Option<f64>,
    pub leap_status: LeapStatus,
    pub rejected_fields: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapStatus {
    Normal,
    InsertSecond,
    DeleteSecond,
    NotSynchronised,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSync {
    pub ntp_enabled: Option<bool>,
    pub synchronized: Option<bool>,
    pub timezone: Option<String>,
    pub rejected_fields: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub max_offset_seconds: f64,
    pub max_stratum: u32,
    pub require_synchronized: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindReason {
    NoOffset,
    NotSynchronised,
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NtpHealth {
    Healthy,
    BlindSpot(BlindReason),
    Drift { offset: f64 },
    Stratum { stratum: u32 },
    Unsynchronised,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Measure {
    pub name: &'static str,
    pub unit: &'static str,
    pub value: f64,
}


pub fn default_flap_restarts() -> u32 {
    DEFAULT_FLAP_RESTARTS
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub unit: String,
    pub should_run: bool,
    pub should_be_enabled: bool,
    #[serde(default = "default_flap_restarts")]
    pub flap_restarts: u32,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectationsFile {
    pub units: Vec<Expectation>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Loaded,
    NotFound,
    Masked,
    Error,
    BadSetting,
    Stub,
    Merged,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveState {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Reloading,
    Maintenance,
    Refreshing,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitFileState {
    Enabled,
    EnabledRuntime,
    Linked,
    LinkedRuntime,
    Alias,
    Masked,
    MaskedRuntime,
    Static,
    Indirect,
    Disabled,
    Generated,
    Transient,
    Bad,
    Empty,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitState {
    pub load: Option<LoadState>,
    pub active: Option<ActiveState>,
    pub sub_state: Option<String>,
    pub file_state: Option<UnitFileState>,
    pub restarts: u32,
    pub exec_main_status: u32,
    pub unknown_values: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitHealth {
    Healthy,
    NotFound,
    NotLoaded,
    Failed,
    Flapping { restarts: u32 },
    Stopped,
    Disabled,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excerpt {
    pub lines: Vec<String>,
    pub omitted: usize,
    pub input_truncated: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimerExpectation {
    pub timer: String,
    pub service: Option<String>,
    pub max_age_seconds: u64,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimerExpectationsFile {
    pub timers: Vec<TimerExpectation>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerState {
    pub load: Option<LoadState>,
    pub unit: Option<String>,
    pub active: Option<ActiveState>,
    pub last_trigger_unix: Option<u64>,
    pub next_elapse_unix: Option<u64>,
    pub unknown_values: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceResult {
    Success,
    Protocol,
    Timeout,
    ExitCode,
    Signal,
    CoreDump,
    Watchdog,
    StartLimitHit,
    Resources,
    OomKill,
    ExecCondition,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRun {
    pub result: Option<ServiceResult>,
    pub exec_main_status: u32,
    pub last_exit_unix: Option<u64>,
    pub unknown_values: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerHealth {
    Healthy,
    NotFound,
    NotLoaded,
    WrongService,
    LastRunFailed,
    Overdue,
    BlindSpot,
    Inactive,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgSettings {
    pub max_connections: u32,
    pub in_recovery: bool,
    pub version_num: u32,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgConnections {
    pub client_backends: u32,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgActivity {
    pub durations_ms: Vec<u64>,
    pub at_least: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaState {
    Startup,
    Catchup,
    Streaming,
    Backup,
    Stopping,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgReplica {
    pub application_name: Option<String>,
    pub state: Option<ReplicaState>,
    pub replay_lag_ms: Option<u64>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgReplication {
    pub replicas: Vec<PgReplica>,
    pub rejected_names: usize,
    pub unknown_values: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbRole {
    Primary,
    Replica,
    #[serde(rename = "any")]
    Unconstrained,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbExpectation {
    pub name: String,
    pub role: DbRole,
    pub max_connections_ratio: f64,
    pub slow_query_ms: u64,
    pub max_replay_lag_ms: u64,
    pub min_replicas: u32,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbExpectationsFile {
    pub databases: Vec<DbExpectation>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbHealth {
    Healthy,
    BlindSpot,
    WrongRole,
    ReplicaMissing,
    ReplicationLag { lag_ms: u64 },
    Saturated { connections: u32 },
    SlowQueries { count: usize },
}
