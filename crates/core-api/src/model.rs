use crate::types::{AccessTable, KeyedLimiter};
use axum::http::StatusCode;
use core_audit::log::AuditLog;
use core_auth::service::State;
use core_auth::types::{Clock, CompromisedSet, RandomFn, RoleCatalog, StoreKey};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use utoipa::ToSchema;


pub struct ApiState {
    pub module: String,
    pub tenant: String,
    pub auth: Mutex<State>,
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
    PayloadTooLarge,
    TooManyRequests,
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
