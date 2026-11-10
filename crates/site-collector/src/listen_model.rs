use crate::model::Collector;
use crate::spool_model::Spool;
use crate::types::Millis;
use arc_swap::ArcSwap;
use serde::Deserialize;
use std::net::{IpAddr, UdpSocket};
use std::sync::{Arc, Mutex};


pub const SETTINGS_SECTION: &str = "listener";


pub const DEFAULT_RATE_PER_SECOND: u64 = 1000;


pub const DEFAULT_BURST: u64 = 2000;


pub const DEFAULT_SOURCE_SHARE_PERCENT: u64 = 50;


pub const DEFAULT_MAX_SOURCES: usize = 4096;


pub const MAX_TENANT_BYTES: usize = 128;


pub const READ_TIMEOUT_MS: u64 = 200;


pub const ERROR_BACKOFF_MS: u64 = 10;


pub const PRUNE_INTERVAL_MS: Millis = 60_000;


pub const IDLE_SOURCE_MS: Millis = 300_000;


pub const SEVERITY_MASK: u8 = 7;


pub const HIGH_SEVERITY_MAX: u8 = 3;


pub const MAX_CYCLES: u64 = u64::MAX;


pub fn default_rate_per_second() -> u64 {
    DEFAULT_RATE_PER_SECOND
}


pub fn default_burst() -> u64 {
    DEFAULT_BURST
}


pub fn default_source_share_percent() -> u64 {
    DEFAULT_SOURCE_SHARE_PERCENT
}


pub fn default_unknown_share_percent() -> u64 {
    crate::model::DEFAULT_UNKNOWN_SHARE_PERCENT
}


pub fn default_max_sources() -> usize {
    DEFAULT_MAX_SOURCES
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerSettings {
    pub listen: String,
    pub tenant: String,
    #[serde(default = "default_rate_per_second")]
    pub rate_per_second: u64,
    #[serde(default = "default_burst")]
    pub burst: u64,
    #[serde(default = "default_source_share_percent")]
    pub source_share_percent: u64,
    #[serde(default = "default_unknown_share_percent")]
    pub unknown_share_percent: u64,
    #[serde(default = "default_max_sources")]
    pub max_sources: usize,
    #[serde(default)]
    pub drop_unknown: bool,
    #[serde(default)]
    pub sources: Vec<IpAddr>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerStats {
    pub received: u64,
    pub accepted: u64,
    pub dropped_rate: u64,
    pub dropped_table_full: u64,
    pub dropped_too_long: u64,
    pub dropped_parse: u64,
    pub dropped_unknown: u64,
    pub spool_errors: u64,
    pub receive_errors: u64,
}


#[derive(Debug)]
pub struct Bound {
    pub listen: String,
    pub socket: UdpSocket,
}


#[derive(Debug)]
pub struct SharedSocket {
    pub bound: ArcSwap<Bound>,
    pub pending: Mutex<Option<Bound>>,
}


#[derive(Debug)]
pub struct Runtime {
    pub collector: Collector,
    pub spool: Spool,
    pub stats: ListenerStats,
    pub applied: Arc<ListenerSettings>,
    pub last_prune_ms: Millis,
}
