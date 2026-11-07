use crate::types::{AccessTable, ConnectionTable, KeyedLimiter, SharedHttpFn, SharedLimits, SharedResolveFn, VerifyPasswordFn};
use arc_swap::{ArcSwap, ArcSwapOption};
use axum::http::StatusCode;
use core_audit::log::AuditLog;
use core_auth::oidc::OidcConfig;
use core_auth::service::State;
use core_auth::types::{Clock, CompromisedSet, PendingMap, RandomFn, RoleCatalog, StoreKey};
use core_config::model::ModuleConfig;
use rustls::ServerConfig;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tracing::level_filters::LevelFilter;
use tracing::Dispatch;
use utoipa::ToSchema;


pub struct ApiState {
    pub module: String,
    pub tenant: String,
    pub auth: std::sync::Mutex<State>,
    pub audit: AuditLog<File>,
    pub key: StoreKey,
    pub compromised: ArcSwap<CompromisedSet>,
    pub catalog: RoleCatalog,
    pub random: RandomFn,
    pub clock: Clock,
    pub store_path: PathBuf,
    pub limiter: KeyedLimiter,
    pub access: AccessTable,
    pub document: serde_json::Value,
    pub verify: VerifyPasswordFn,
    pub hashing: Arc<Semaphore>,
    pub dispatch: Dispatch,
    pub limits: SharedLimits,
    pub oidc: ArcSwapOption<OidcRuntime>,
    pub callback_accounts: std::sync::Mutex<BTreeSet<String>>,
}


/// The settings that change at run time; readers load one whole value, lock-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub rate_max_requests: u32,
    pub rate_window_seconds: i64,
    pub max_sources: usize,
    pub max_attempts: usize,
    pub body_read_timeout: Duration,
    pub max_connections_per_source: usize,
}


/// `fingerprint` is keyed by a per-process salt that is never written, so it decides swaps without being recomputable from the audit; it digests the provider files, so a reload swaps the runtime (and drops its pending logins) only when they changed.
pub struct OidcRuntime {
    pub fingerprint: String,
    pub config: OidcConfig,
    pub http: SharedHttpFn,
    pub resolve: SharedResolveFn,
    pub pending: std::sync::Mutex<PendingMap>,
    pub refresh: core_auth::oidc::KeyRefreshGate,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub started: OffsetDateTime,
    pub count: u32,
}


#[derive(Debug)]
pub struct ConnectionGuard {
    pub table: ConnectionTable,
    pub source: IpAddr,
}


impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        let remaining = table.get(&self.source).copied().unwrap_or(0).saturating_sub(1);
        if remaining == 0 {
            table.remove(&self.source);
        } else {
            table.insert(self.source, remaining);
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    pub module: String,
    pub tenant: String,
    pub address: SocketAddr,
    pub tls: Option<TlsFiles>,
    pub accounts_store: PathBuf,
    pub audit_log: PathBuf,
    pub key_file: String,
    pub compromised_list: PathBuf,
    pub header_read_timeout: Duration,
    pub limits: Limits,
    pub log_level: LevelFilter,
    pub oidc: Option<OidcFiles>,
}


/// One whole, validated configuration: what the reload engine swaps. Files are read and checked before it exists.
pub struct ApiSettings {
    pub module: ModuleConfig,
    pub config: ApiConfig,
    pub tls: Option<Arc<ServerConfig>>,
    pub oidc: Option<Arc<OidcRuntime>>,
    pub compromised: Arc<CompromisedSet>,
    pub fingerprints: BTreeMap<String, String>,
}


/// A TLS pair read once: the digests are of the bytes the configuration was parsed from.
pub struct LoadedTls {
    pub config: ServerConfig,
    pub certificate_digest: String,
    pub key_digest: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcFiles {
    pub config: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub secret_file: PathBuf,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    Public,
    Session,
    Permission(String),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub requirement: Requirement,
    pub sensitive: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);


#[derive(Debug, Clone)]
pub struct Authenticated {
    pub user: String,
    pub token: SecretString,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    BadRequest,
    Unauthorized,
    InvalidCredentials,
    MfaRequired,
    MfaInvalid,
    MfaEnrolmentRequired,
    Forbidden,
    RequestTimeout,
    PayloadTooLarge,
    TooManyRequests,
    BadGateway,
    Internal,
}


#[derive(Debug)]
pub struct Decision {
    pub actor: String,
    pub session: Option<Authenticated>,
    pub error: Option<ApiError>,
}


#[derive(Debug, Clone)]
pub struct Exchange {
    pub request_id: String,
    pub actor: String,
    pub route: String,
    pub state_changing: bool,
    pub sensitive: bool,
    pub source: String,
    pub status: StatusCode,
}


#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginBody {
    pub username: String,
    #[schema(value_type = String)]
    pub password: SecretString,
    #[schema(value_type = Option<String>)]
    pub totp_code: Option<SecretString>,
}


#[derive(Debug, Serialize, ToSchema)]
pub struct HealthReply {
    pub status: String,
}


#[derive(Debug, Serialize, ToSchema)]
pub struct LoginReply {
    pub token: String,
    pub token_type: String,
}


#[derive(Debug, Serialize, ToSchema)]
pub struct MeReply {
    pub username: String,
    pub roles: Vec<String>,
    pub mfa_enrolled: bool,
}


#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}


#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}


#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub state: Option<String>,
    pub code: Option<SecretString>,
    pub error: Option<String>,
}


#[derive(Debug, Serialize, ToSchema)]
pub struct StartReply {
    pub authorization_url: String,
}
