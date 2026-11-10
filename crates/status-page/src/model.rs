use crate::types::{NowFn, SharedSettings, SourceConnections};
use arc_swap::ArcSwapOption;
use ipnet::IpNet;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentConfig {
    pub name: String,
    pub service: String,
    pub objective_ppm: Option<u32>,
    #[serde(default)]
    pub rule: Option<RuleConfig>,
}


/// State rule of one component: counts of failing locations, `recover_after` consecutive passes, results older than the window ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub checks: Vec<String>,
    pub degraded_after: u32,
    pub down_after: u32,
    pub recover_after: u32,
    pub window_seconds: u32,
    #[serde(default)]
    pub unknown_state: Option<ComponentState>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageConfig {
    pub id: String,
    pub tenant: String,
    pub title: String,
    #[serde(default)]
    pub checks: Vec<String>,
    pub components: Vec<ComponentConfig>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_components: usize,
    pub max_incidents: usize,
    pub max_updates: usize,
    pub max_text_bytes: usize,
    pub max_json_bytes: usize,
    pub max_html_bytes: usize,
}


pub const DEFAULT_LIMITS: Limits = Limits {
    max_components: 200,
    max_incidents: 500,
    max_updates: 100,
    max_text_bytes: 2048,
    max_json_bytes: 1_048_576,
    max_html_bytes: 2_097_152,
};


/// Declaration order is the severity order; `Maintenance` and `Unknown` never count in the worst state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Operational,
    Degraded,
    PartialOutage,
    MajorOutage,
    Maintenance,
    Unknown,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    pub tenant: String,
    pub service: String,
    pub state: ComponentState,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub tenant: String,
    pub check: String,
    pub location: String,
    pub at: i64,
    pub passed: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualOverride {
    pub tenant: String,
    pub service: String,
    pub state: ComponentState,
    pub author: String,
    pub expires_at: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentUpdateInput {
    pub at: i64,
    pub message: String,
    pub internal_note: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentInput {
    pub tenant: String,
    pub service: String,
    pub published: bool,
    pub public_title: String,
    pub started_at: i64,
    pub resolved_at: Option<i64>,
    pub updates: Vec<IncidentUpdateInput>,
    pub internal_note: String,
    pub assignee: String,
    pub asset_ids: Vec<String>,
    pub addresses: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FigureInput {
    pub tenant: String,
    pub service: String,
    pub availability_ppm: Option<u32>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicFigure {
    pub availability_ppm: Option<u32>,
    pub objective_ppm: Option<u32>,
    pub objective_met: Option<bool>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicComponent {
    pub name: String,
    pub state: ComponentState,
    pub figure: Option<PublicFigure>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicUpdate {
    pub at: i64,
    pub message: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicIncident {
    pub title: String,
    pub component: String,
    pub started_at: i64,
    pub resolved_at: Option<i64>,
    pub updates: Vec<PublicUpdate>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicPage {
    pub id: String,
    pub title: String,
    pub generated_at: i64,
    pub state: ComponentState,
    pub maintenance: bool,
    pub components: Vec<PublicComponent>,
    pub incidents: Vec<PublicIncident>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
    pub states: usize,
    pub incidents: usize,
    pub figures: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    pub json: String,
    pub html: String,
    pub dropped: Dropped,
}


pub const SETTINGS_SECTION: &str = "status_page";


pub const DEFAULT_RATE_PER_SECOND: u32 = 5;


pub const DEFAULT_BURST: u32 = 20;


pub const DEFAULT_MAX_SOURCES: usize = 10_000;


pub const DEFAULT_MAX_CONNECTIONS: usize = 256;


pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 8;


pub const DEFAULT_HEADER_READ_TIMEOUT_SECONDS: u64 = 10;


pub const DEFAULT_CONNECTION_TIMEOUT_SECONDS: u64 = 30;


pub const DEFAULT_MAX_HEADERS: usize = 32;


pub const MIN_HEADER_BYTES: usize = 8192;


pub const DEFAULT_MAX_HEADER_BYTES: usize = 16_384;


pub const DEFAULT_CACHE_MAX_AGE_SECONDS: u64 = 15;


pub const DEFAULT_MAX_PROXY_HEADER_BYTES: usize = 512;


pub const DEFAULT_WIDE_PREFIX_BITS: u8 = 48;


pub const DEFAULT_WIDE_MULTIPLIER: u32 = 8;


pub const MIN_PROXY_HEADER_BYTES: usize = 52;


pub const MAX_PROXY_HEADER_BYTES_LIMIT: usize = 4096;


pub const MAX_TRUSTED_PROXIES: usize = 256;


pub const MAX_WIDE_MULTIPLIER: u32 = 1024;


pub const MAX_WIDE_PREFIX_BITS: u8 = 64;


pub const MAX_SOURCES_LIMIT: usize = 1_000_000;


pub const MAX_CONNECTIONS_LIMIT: usize = 65_536;


pub const MAX_CONNECTIONS_PER_SOURCE_LIMIT: usize = 1024;


pub const MAX_HEADER_READ_TIMEOUT_SECONDS: u64 = 300;


pub const MAX_CONNECTION_TIMEOUT_SECONDS: u64 = 3600;


pub const MAX_HEADERS_LIMIT: usize = 1024;


pub const MAX_HEADER_BYTES_LIMIT: usize = 1_048_576;


/// The serving settings file; every bound is nonzero, applied from the next request (the connection bounds from the next connection).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PageSettings {
    pub rate_per_second: u32,
    pub burst: u32,
    pub max_sources: usize,
    pub max_connections: usize,
    pub max_connections_per_source: usize,
    pub header_read_timeout_seconds: u64,
    pub connection_timeout_seconds: u64,
    pub max_headers: usize,
    pub max_header_bytes: usize,
    pub cache_max_age_seconds: u64,
    pub trusted_proxies: Vec<IpNet>,
    pub max_proxy_header_bytes: usize,
    pub wide_prefix_bits: u8,
    pub wide_multiplier: u32,
}


impl Default for PageSettings {
    fn default() -> Self {
        Self {
            rate_per_second: DEFAULT_RATE_PER_SECOND,
            burst: DEFAULT_BURST,
            max_sources: DEFAULT_MAX_SOURCES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_source: DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
            header_read_timeout_seconds: DEFAULT_HEADER_READ_TIMEOUT_SECONDS,
            connection_timeout_seconds: DEFAULT_CONNECTION_TIMEOUT_SECONDS,
            max_headers: DEFAULT_MAX_HEADERS,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            cache_max_age_seconds: DEFAULT_CACHE_MAX_AGE_SECONDS,
            trusted_proxies: Vec::new(),
            max_proxy_header_bytes: DEFAULT_MAX_PROXY_HEADER_BYTES,
            wide_prefix_bits: DEFAULT_WIDE_PREFIX_BITS,
            wide_multiplier: DEFAULT_WIDE_MULTIPLIER,
        }
    }
}


/// What the readers are served: one rendered page, swapped whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub tenant: String,
    pub html: String,
    pub json: String,
    pub etag: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    pub tokens_milli: u64,
    pub last_millis: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    Limited { retry_after_seconds: u64 },
}


/// The peer of a connection, attached to each of its requests by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIp(pub IpAddr);


/// Everything the handlers share; the tenant is the one of the page config.
pub struct PageState {
    pub tenant: String,
    pub snapshot: ArcSwapOption<Snapshot>,
    pub settings: SharedSettings,
    pub buckets: Mutex<LruCache<IpAddr, Bucket>>,
    pub wide_buckets: Mutex<LruCache<IpAddr, Bucket>>,
    pub now: Box<NowFn>,
    pub active: Arc<AtomicUsize>,
    pub sources: SourceConnections,
    pub wide_sources: SourceConnections,
    pub proxy_malformed: AtomicUsize,
}


/// The bounds a new connection is admitted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCaps {
    pub per_source: usize,
    pub per_wide: usize,
    pub maximum: usize,
    pub wide_bits: u8,
}


/// What a PROXY protocol v2 header from a trusted proxy said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyOutcome {
    Client(IpAddr),
    Local,
    Malformed,
}


/// Counts one open connection, globally and for its source key; the count goes back down when it is dropped.
pub struct ConnectionGuard {
    pub active: Arc<AtomicUsize>,
    pub sources: SourceConnections,
    pub key: IpAddr,
    pub wide_sources: SourceConnections,
    pub wide_key: Option<IpAddr>,
}
