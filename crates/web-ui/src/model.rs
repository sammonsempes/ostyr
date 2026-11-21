use crate::types::{AttemptTable, ClockFn, Random, SessionTable, WallFn};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    French,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}


/// One alert as the REST API returns it (contract of T168).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub severity: Severity,
    pub event_time: String,
    pub created: String,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
    pub event_ids: Vec<String>,
    pub summary: Map<String, Value>,
    pub summary_truncated: bool,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AlertPage {
    pub items: Vec<Alert>,
    pub next_cursor: Option<String>,
}


/// How many entries each growing list of a case holds (contract of the cases module).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct CaseCountsView {
    pub tasks: u64,
    pub observables: u64,
    pub comments: u64,
    pub history: u64,
    pub alerts: u64,
}


/// One case of a list; `severity` and `status` stay text so an unknown value is shown as a fixed string, never refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CaseSummaryView {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub assignee: Option<String>,
    pub case_type: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub counts: CaseCountsView,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CaseTaskView {
    pub title: String,
    pub status: String,
    pub due: Option<i64>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CaseDetailView {
    #[serde(flatten)]
    pub summary: CaseSummaryView,
    pub description: Option<String>,
    pub resolution: Option<String>,
    pub template: Option<String>,
    pub tasks: Vec<CaseTaskView>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CommentView {
    pub author: String,
    pub at: i64,
    pub text: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CasePageView {
    pub items: Vec<CaseSummaryView>,
    pub next_cursor: Option<String>,
}


/// How many entries an asset holds; the CMDB's `version` field is ignored (the pages do not show it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct AssetCountsView {
    pub keys: u64,
    pub attributes: u64,
    pub open_conflicts: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AssetSummaryView {
    pub id: String,
    pub kind: String,
    pub lifecycle: String,
    pub counts: AssetCountsView,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AssetKeyView {
    pub key: String,
    pub value: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AssetAttributeView {
    pub name: String,
    pub value: String,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AssetDetailView {
    #[serde(flatten)]
    pub summary: AssetSummaryView,
    pub keys: Vec<AssetKeyView>,
    pub attributes: Vec<AssetAttributeView>,
    pub truncated: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AssetPageView {
    pub items: Vec<AssetSummaryView>,
    pub next_cursor: Option<String>,
}


/// The bound that stopped a risk computation; `limit` stays text and is shown through a fixed table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RiskTruncatedView {
    pub limit: String,
    pub read: u64,
    pub cap: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RiskEntityView {
    pub kind: String,
    pub id: String,
    pub value: u64,
    pub contributions_used: u64,
    pub contributions_dropped: u64,
}


/// `GET /risk/entities`; the `informational` and `refused` fields of the API are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RiskListView {
    pub computed_at: i64,
    pub alerts_read: u64,
    pub truncated: Option<RiskTruncatedView>,
    pub entities: Vec<RiskEntityView>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RiskDetailView {
    pub computed_at: i64,
    pub truncated: Option<RiskTruncatedView>,
    pub entity: RiskEntityView,
}


/// `GET /certificates` items; every text is free text of a scanned file or a CT log.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CertView {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub first_seen: String,
    pub last_seen: String,
    pub key_type: String,
    pub key_bits: Option<u64>,
    pub self_signed: bool,
    pub expiry: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CertListView {
    pub items: Vec<CertView>,
    pub skipped: u64,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SightingView {
    pub kind: String,
    pub reference: String,
    pub last_seen: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CertDetailView {
    #[serde(flatten)]
    pub cert: CertView,
    pub sightings: Vec<SightingView>,
    pub sightings_skipped: u64,
    pub sightings_truncated: bool,
}


/// `GET /hunts/findings` items; the pack id and both window ends are checked before they are printed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FindingView {
    pub pack_id: String,
    pub window_start: String,
    pub window_end: String,
    pub matches: i64,
    pub max_matches: i64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OversizedView {
    pub count: i64,
    pub capped: bool,
}


/// `GET /compliance/state` and `GET /compliance/assets/{asset}` items; every field is checked before it is printed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StateView {
    pub baseline: String,
    pub control: String,
    pub asset: String,
    pub verdict: String,
    pub first_failed: Option<String>,
    pub last_seen: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StateListView {
    pub items: Vec<StateView>,
    pub skipped: u64,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StateAssetView {
    pub items: Vec<StateView>,
    pub skipped: u64,
    pub truncated: bool,
}


/// `GET /vulnerabilities/findings` and `GET /vulnerabilities/assets/{asset}` items; the scores stay raw so a forged one is a row marker.
#[derive(Debug, Clone, Deserialize)]
pub struct VulnView {
    pub asset: String,
    pub ecosystem: String,
    pub package: String,
    pub record_id: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub cvss: Box<RawValue>,
    pub epss: Box<RawValue>,
    pub kev: bool,
    pub priority: u32,
    pub first_seen: String,
    pub last_seen: String,
}


#[derive(Debug, Clone, Deserialize)]
pub struct VulnListView {
    pub items: Vec<VulnView>,
    pub skipped: u64,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, Deserialize)]
pub struct VulnAssetView {
    pub items: Vec<VulnView>,
    pub skipped: u64,
    pub truncated: bool,
}


/// `GET /oncall/alerts` items and `GET /oncall/alerts/{id}`; every field is checked before it is printed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OncallAlertView {
    pub id: i64,
    pub fingerprint: String,
    pub state: String,
    pub level: u32,
    pub occurrences: i64,
    pub opened_at: String,
    pub acknowledged_at: Option<String>,
    pub resolved_at: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OncallListView {
    pub items: Vec<OncallAlertView>,
    pub skipped: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FindingsView {
    pub items: Vec<FindingView>,
    pub skipped: u64,
    pub oversized: OversizedView,
    pub next_cursor: Option<String>,
}


/// The API token stays on the server; the browser holds only the random session identifier.
pub struct Session {
    pub username: String,
    pub token: SecretString,
    pub csrf: String,
    pub expires: u64,
}


/// What a handler needs of a session, copied out of the table so no lock is held across a call.
pub struct Principal {
    pub key: String,
    pub token: SecretString,
    pub csrf: String,
}


#[derive(Debug, Clone, Copy)]
pub struct Window {
    pub started: u64,
    pub count: u32,
}


#[derive(Debug, Clone, Copy)]
pub struct WebLimits {
    pub session_seconds: u64,
    pub form_timeout: Duration,
    pub form_bytes: usize,
    pub login_max: u32,
    pub login_window_seconds: u64,
    pub max_sources: usize,
}


pub struct ApiClient {
    pub http: reqwest::Client,
    pub base: String,
    pub permits: Arc<Semaphore>,
    pub login_permits: Arc<Semaphore>,
    pub deadline: Duration,
}


/// A new session identifier and the API tokens of the sessions the per-account cap dropped.
pub struct Opened {
    pub id: String,
    pub evicted: Vec<SecretString>,
}


/// A validated runtime built before a reload swaps anything.
pub struct Prepared {
    pub client: ApiClient,
    pub tls: Option<Arc<ServerConfig>>,
    pub user_sessions: usize,
    pub sessions: usize,
}


pub struct WebState {
    pub api: ArcSwap<ApiClient>,
    pub sessions: SessionTable,
    pub attempts: AttemptTable,
    pub user_sessions_max: AtomicUsize,
    pub sessions_max: AtomicUsize,
    pub limits: WebLimits,
    pub clock: ClockFn,
    pub wall: WallFn,
    pub random: Random,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub certificate: PathBuf,
    pub key: PathBuf,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawApiSection {
    pub base_url: String,
    pub ca: Option<PathBuf>,
    pub timeout_seconds: u64,
    #[serde(default = "default_api_connections")]
    pub max_connections: usize,
}


pub const DEFAULT_API_CONNECTIONS: usize = 16;


pub const DEFAULT_USER_SESSIONS: usize = 5;


pub const DEFAULT_SESSIONS: usize = 10_000;


pub fn default_api_connections() -> usize {
    DEFAULT_API_CONNECTIONS
}


pub fn default_user_sessions() -> usize {
    DEFAULT_USER_SESSIONS
}


pub fn default_sessions() -> usize {
    DEFAULT_SESSIONS
}


/// `base_url` is normalised to end with a slash.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawApiSection")]
pub struct ApiSection {
    pub base_url: String,
    pub ca: Option<PathBuf>,
    pub timeout_seconds: u64,
    pub max_connections: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    pub listen: SocketAddr,
    pub tls: Option<TlsSection>,
    pub api: ApiSection,
    pub audit_file: PathBuf,
    #[serde(default = "default_user_sessions")]
    pub max_sessions_per_user: usize,
    #[serde(default = "default_sessions")]
    pub max_sessions: usize,
}


/// One lease interval of `GET /dhcp/leases/at` and `GET /dhcp/leases/mac`; every field is checked before it is printed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LeaseView {
    pub address: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub starts: String,
    pub ends: String,
    pub action: String,
    pub subnet_id: i64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LookupView {
    pub intervals: Vec<LeaseView>,
    pub skipped: u64,
    pub truncated: bool,
}


/// A checked browser lookup: values already inside the API's grammar, so the path is built from typed values only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpQuery {
    At { address: IpAddr, at: i64 },
    Mac { mac: String, from: i64, to: i64 },
}


/// One row of the remote-shell register; every field is checked before it is printed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ShellSessionView {
    pub session_id: String,
    pub requester: String,
    pub asset: String,
    pub ticket: String,
    pub opened_at: String,
    pub closed_at: Option<String>,
    pub close_reason: Option<String>,
    pub recording_frames: Option<i64>,
    pub recording_hash: Option<String>,
    pub recording_bytes: Option<i64>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ShellListView {
    pub items: Vec<ShellSessionView>,
    pub skipped: u64,
    pub next_cursor: Option<String>,
}


/// A checked browser query: every value is already inside the API's grammar; `open` is one of the two fixed words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellQuery {
    pub asset: Option<String>,
    pub requester: Option<String>,
    pub open: Option<&'static str>,
    pub cursor: Option<String>,
}


/// How a closed session ended, every part checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellEnd {
    pub closed_at: String,
    pub reason_key: &'static str,
    pub frames: i64,
    pub hash: String,
    pub bytes: i64,
}


/// A readable register row: the open time and, once closed, how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellFacts {
    pub opened_at: String,
    pub end: Option<ShellEnd>,
}
