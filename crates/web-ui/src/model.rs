use crate::types::{AttemptTable, ClockFn, Random, SessionTable};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::net::SocketAddr;
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
