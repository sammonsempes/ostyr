use crate::settings::deserialize_address;
use crate::types::{BoxRead, BoxWrite, ConnectFn};
use serde::Deserialize;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;


pub const DEFAULT_MAX_CONNECTIONS: usize = 400;


pub const MAX_CONNECTIONS_LIMIT: usize = 65_536;


/// Agents behind one NAT (10) times the TCP connections one agent holds (one channel run, one more while a run replaces the previous).
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 20;


pub const DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 5;


pub const DEFAULT_IDLE_SECONDS: u64 = 120;


pub const DEFAULT_MAX_LIFETIME_SECONDS: u64 = 3600;


/// The 12-byte signature that opens every PROXY protocol v2 header.
pub const PROXY_V2_SIGNATURE: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];


/// Version 2 in the high nibble, command PROXY in the low one.
pub const PROXY_V2_VERSION_COMMAND: u8 = 0x21;


/// Address family IPv4 in the high nibble, transport stream in the low one.
pub const PROXY_V2_TCP4: u8 = 0x11;


/// Address family IPv6 in the high nibble, transport stream in the low one.
pub const PROXY_V2_TCP6: u8 = 0x21;


/// Two IPv4 addresses and two ports.
pub const PROXY_V2_TCP4_LENGTH: u16 = 12;


/// Two IPv6 addresses and two ports.
pub const PROXY_V2_TCP6_LENGTH: u16 = 36;


/// Keeps `Instant + Duration` far from overflow.
pub const MAX_SECONDS_LIMIT: u64 = 604_800;


/// Mirror of agent-channel `CONNECT_TIMEOUT_SECONDS`; a test pins the equality.
pub const AGENT_CONNECT_TIMEOUT_SECONDS: u64 = 10;


/// Mirror of agent-channel `SERVER_KEEPALIVE_INTERVAL_SECONDS`.
pub const AGENT_KEEPALIVE_SECONDS: u64 = 20;


/// Mirror of agent-channel `PREFERRED_RETRY_SECONDS`.
pub const AGENT_PREFERRED_RETRY_SECONDS: u64 = 300;


/// Mirror of agent-channel `UNARY_TIMEOUT_SECONDS`.
pub const AGENT_UNARY_TIMEOUT_SECONDS: u64 = 30;


pub const KEEPALIVE_FACTOR: u64 = 2;


pub const LIFETIME_MARGIN_SECONDS: u64 = 30;


pub const MIN_IDLE_SECONDS: u64 = AGENT_KEEPALIVE_SECONDS * KEEPALIVE_FACTOR;


pub const MIN_LIFETIME_SECONDS: u64 = AGENT_PREFERRED_RETRY_SECONDS + AGENT_UNARY_TIMEOUT_SECONDS + LIFETIME_MARGIN_SECONDS;


pub const DESCRIPTORS_PER_CONNECTION: u64 = 2;


pub const RESERVED_FDS: u64 = 64;


pub const BUFFER_BYTES: usize = 8192;


pub const SUMMARY_SECONDS: u64 = 60;


pub const SHUTDOWN_GRACE_SECONDS: u64 = 30;


pub const ACCEPT_ERROR_PAUSE_MILLIS: u64 = 100;


pub const MAX_SETTINGS_BYTES: u64 = 4096;


pub const IPV6_HOST_BITS: u32 = 64;


pub const DEBOUNCE_MILLIS: u64 = 300;


pub const MODULE: &str = "relay";


pub const SETTINGS_SECTION: &str = "relay";


pub const SETTINGS_FILE_CLASS: &str = "settings file";


pub const ALLOWED_PUNCTUATION: &[u8] = b" \n._:[]-\"'";


pub const DECLARED_KEYS: [&str; 9] = [
    "result",
    "diff",
    "reason",
    "changed_settings",
    "changed_files",
    "diff_sha256",
    "listen",
    "upstream",
    "cut",
];


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySettings {
    #[serde(deserialize_with = "deserialize_address")]
    pub listen: SocketAddr,
    #[serde(deserialize_with = "deserialize_address")]
    pub upstream: SocketAddr,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_connections_per_source")]
    pub max_connections_per_source: usize,
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_idle_seconds")]
    pub idle_seconds: u64,
    #[serde(default = "default_max_lifetime_seconds")]
    pub max_lifetime_seconds: u64,
}


pub fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}


pub fn default_max_connections_per_source() -> usize {
    DEFAULT_MAX_CONNECTIONS_PER_SOURCE
}


pub fn default_connect_timeout_seconds() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECONDS
}


pub fn default_idle_seconds() -> u64 {
    DEFAULT_IDLE_SECONDS
}


pub fn default_max_lifetime_seconds() -> u64 {
    DEFAULT_MAX_LIFETIME_SECONDS
}


/// The two halves of one TCP connection, boxed so tests can use in-memory streams.
pub struct Halves {
    pub read: BoxRead,
    pub write: BoxWrite,
}


pub struct Accepted {
    pub halves: Halves,
    pub peer: io::Result<SocketAddr>,
    pub local: io::Result<SocketAddr>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub connect: Duration,
    pub idle: Duration,
    pub lifetime: Duration,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    Completed,
    CopyError,
    Idle,
    Lifetime,
    Cut,
    ConnectFailed,
    ConnectTimeout,
    HeaderFailed,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the total connection cap is reached")]
    Total,
    #[error("the per-source connection cap is reached")]
    Source,
}


#[derive(Debug, Default)]
pub struct AdmissionState {
    pub total: usize,
    pub sources: HashMap<IpAddr, usize>,
}


#[derive(Debug)]
pub struct Admission {
    pub state: Mutex<AdmissionState>,
    pub live: watch::Sender<usize>,
}


/// Held from before the upstream connect until both sockets are closed.
#[derive(Debug)]
pub struct Permit {
    pub admission: Arc<Admission>,
    pub source: IpAddr,
}


#[derive(Debug, Default)]
pub struct Counters {
    pub refused_total: AtomicU64,
    pub refused_source: AtomicU64,
    pub connect_failed: AtomicU64,
    pub connect_timeout: AtomicU64,
    pub header_failed: AtomicU64,
    pub idle_end: AtomicU64,
    pub lifetime_end: AtomicU64,
    pub copy_error: AtomicU64,
    pub accept_error: AtomicU64,
    pub peer_unknown: AtomicU64,
    pub completed: AtomicU64,
    pub shutdown_cut: AtomicU64,
}


/// One window of counts and the gauges at its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub refused_total: u64,
    pub refused_source: u64,
    pub connect_failed: u64,
    pub connect_timeout: u64,
    pub header_failed: u64,
    pub idle_end: u64,
    pub lifetime_end: u64,
    pub copy_error: u64,
    pub accept_error: u64,
    pub peer_unknown: u64,
    pub completed: u64,
    pub shutdown_cut: u64,
    pub live: usize,
    pub sources: usize,
}


pub struct Server {
    pub engine: Arc<core_config::reload::ReloadEngine<RelaySettings>>,
    pub admission: Arc<Admission>,
    pub counters: Counters,
    pub connect: ConnectFn,
    pub cut: watch::Sender<bool>,
}


#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub shutdown_grace: Duration,
    pub summary_every: Duration,
    pub accept_pause: Duration,
}


impl Default for Options {
    fn default() -> Self {
        Self {
            shutdown_grace: Duration::from_secs(SHUTDOWN_GRACE_SECONDS),
            summary_every: Duration::from_secs(SUMMARY_SECONDS),
            accept_pause: Duration::from_millis(ACCEPT_ERROR_PAUSE_MILLIS),
        }
    }
}


#[derive(Debug, Clone)]
pub struct Paths {
    pub settings: std::path::PathBuf,
    pub audit: std::path::PathBuf,
}


/// The audit log, the settings engine and the settings path of one run.
pub struct Runtime {
    pub log: Arc<core_audit::log::AuditLog<std::fs::File>>,
    pub engine: Arc<core_config::reload::ReloadEngine<RelaySettings>>,
    pub audit_lock: std::fs::File,
    pub settings_path: std::path::PathBuf,
}
