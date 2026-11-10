use crate::types::{AttemptTable, ClockFn, Random, SessionTable};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;


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


/// The API token stays on the server; the browser holds only the random session identifier.
pub struct Session {
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
    pub max_sessions: usize,
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
}


/// A validated runtime built before a reload swaps anything.
pub struct Prepared {
    pub client: ApiClient,
    pub tls: Option<Arc<ServerConfig>>,
}


pub struct WebState {
    pub api: ArcSwap<ApiClient>,
    pub sessions: SessionTable,
    pub attempts: AttemptTable,
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
}


/// `base_url` is normalised to end with a slash.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawApiSection")]
pub struct ApiSection {
    pub base_url: String,
    pub ca: Option<PathBuf>,
    pub timeout_seconds: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    pub listen: SocketAddr,
    pub tls: Option<TlsSection>,
    pub api: ApiSection,
    pub audit_file: PathBuf,
}
