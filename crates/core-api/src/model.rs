use crate::error::StartupError;
use crate::server::stop_listener;
use crate::types::{
    AccessTable, ConnectionTable, KeyedLimiter, ServerHandle, SharedHttpFn, SharedLimits, SharedListener, SharedResolveFn, VerifyPasswordFn,
    WatchGuard,
};
use arc_swap::{ArcSwap, ArcSwapOption};
use axum::http::StatusCode;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use core_audit::log::{AuditLog, LogState};
use core_auth::oidc::OidcConfig;
use core_auth::service::State;
use core_auth::types::{Clock, CompromisedSet, PendingMap, RandomFn, RoleCatalog, StoreKey};
use core_config::model::ModuleConfig;
use core_config::reload::ReloadEngine;
use rustls::ServerConfig;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::runtime::Handle;
use tokio::sync::{Notify, Semaphore};
use tracing::level_filters::LevelFilter;
use tracing::Dispatch;
use utoipa::ToSchema;


pub struct ApiState {
    pub identity: ArcSwap<ApiIdentity>,
    pub auth: std::sync::Mutex<State>,
    pub audit: AuditLog<File>,
    pub key: ArcSwap<StoreKey>,
    pub compromised: ArcSwap<CompromisedSet>,
    pub catalog: RoleCatalog,
    pub random: RandomFn,
    pub clock: Clock,
    pub store_path: ArcSwap<PathBuf>,
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


/// The module name and tenant every audit record and log line carries; replaced whole at a reload. `generation` grows only when the name or tenant really changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiIdentity {
    pub module: String,
    pub tenant: String,
    pub generation: u64,
}


/// The key, the list and the OIDC runtime a state starts from, each read once.
pub struct StateInputs {
    pub key: Arc<StoreKey>,
    pub compromised: Arc<CompromisedSet>,
    pub oidc: Option<Arc<OidcRuntime>>,
}


/// What one authentication step reads: taken together so it never mixes the old key with the new tenant.
pub struct AuthInputs {
    pub compromised: Arc<CompromisedSet>,
    pub key: Arc<StoreKey>,
    pub identity: Arc<ApiIdentity>,
}


/// The new store key, read and checked at validation and kept for the swap.
pub struct PreparedKey {
    pub key: Arc<StoreKey>,
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
    pub generations: crate::types::PendingGenerations,
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
    pub key: Arc<StoreKey>,
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


/// Two handles on one listening socket: `kept` stays in `Bound` (so a later server can clone it), `server` goes to the new server.
#[derive(Debug)]
pub struct Sockets {
    pub kept: TcpListener,
    pub server: TcpListener,
}


/// What the running server was started with, to tell whether a reload must start another one.
#[derive(Debug)]
pub struct Bound {
    pub socket: TcpListener,
    pub tls: Option<RustlsConfig>,
    pub address: SocketAddr,
    pub header_read_timeout: Duration,
    pub generation: u64,
}


/// `handle` stops the newest server, `stopped` keeps a later reload from starting another; `bound` is `None` until the first server starts.
#[derive(Debug)]
pub struct Current {
    pub handle: ServerHandle,
    pub bound: Option<Bound>,
    pub stopped: bool,
}


/// The live listener: a reload starts a new server (a new generation) on the new socket and drains the old one.
#[derive(Debug)]
pub struct Listener {
    pub current: Mutex<Current>,
    pub connections: ConnectionTable,
    pub finished: Notify,
    pub outcome: Mutex<Option<Result<(), StartupError>>>,
}


/// A new audit log, opened and verified before the swap.
#[derive(Debug)]
pub struct PreparedAudit {
    pub path: PathBuf,
    pub state: LogState<File>,
}


/// The paths being watched and the guard that watches them.
pub struct Watching {
    pub files: Vec<PathBuf>,
    pub guard: WatchGuard,
}


/// The file watch follows the module file, so it can be replaced by a reload; `engine` is weak so the engine can be dropped.
#[derive(Default)]
pub struct Rewatch {
    pub engine: OnceLock<Weak<ReloadEngine<ApiSettings>>>,
    pub watching: Mutex<Option<Watching>>,
}


/// Stops the watch when dropped: the watch holds the engine, which holds this watch.
pub struct WatchStop(pub Arc<Rewatch>);


impl Drop for WatchStop {
    fn drop(&mut self) {
        self.0.watching.lock().unwrap_or_else(PoisonError::into_inner).take();
    }
}


/// Stops the newest server when dropped, so a start-up that fails after the server began leaves nothing listening.
pub struct ServerStop(pub SharedListener);


impl Drop for ServerStop {
    fn drop(&mut self) {
        stop_listener(&self.0, None);
    }
}


/// Everything a reload needs to move the listener and the file watch.
#[derive(Clone)]
pub struct ListenerSetup {
    pub listener: SharedListener,
    pub router: Router,
    pub limits: SharedLimits,
    pub runtime: Handle,
    pub rewatch: Arc<Rewatch>,
}
