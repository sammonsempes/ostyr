use crate::types::{AccessTable, ConnectionTable, KeyedLimiter, SharedHttpFn, SharedResolveFn, VerifyPasswordFn};
use axum::http::StatusCode;
use core_audit::log::AuditLog;
use core_auth::oidc::OidcConfig;
use core_auth::service::State;
use core_auth::types::{Clock, CompromisedSet, PendingMap, RandomFn, RoleCatalog, StoreKey};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tracing::Dispatch;
use utoipa::ToSchema;


pub struct ApiState {
    pub module: String,
    pub tenant: String,
    pub auth: std::sync::Mutex<State>,
    pub audit: AuditLog<File>,
    pub key: StoreKey,
    pub compromised: CompromisedSet,
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
    pub max_sources: usize,
    pub max_attempts: usize,
    pub body_timeout: Duration,
    pub oidc: Option<OidcRuntime>,
    pub callback_accounts: std::sync::Mutex<BTreeSet<String>>,
}


pub struct OidcRuntime {
    pub config: OidcConfig,
    pub http: SharedHttpFn,
    pub resolve: SharedResolveFn,
    pub pending: std::sync::Mutex<PendingMap>,
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
    pub body_read_timeout: Duration,
    pub max_connections_per_source: usize,
    pub oidc: Option<OidcFiles>,
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
