use core_audit::error::AuditError;
use core_auth::error::AuthError;
use core_config::error::{ConfigError, WatchError};
use core_config::types::BoxError;
use rustls_pki_types::pem;
use std::io;
use std::net::{AddrParseError, SocketAddr};
use thiserror::Error;


#[derive(Debug, Error)]
pub enum StartupError {
    #[error("usage: {0}")]
    Usage(String),
    #[error("setting `{0}` is required")]
    MissingSetting(&'static str),
    #[error("`{value}` is not a socket address: {source}")]
    InvalidAddress {
        value: String,
        #[source]
        source: AddrParseError,
    },
    #[error("tls_certificate and tls_key must be set together")]
    IncompleteTls,
    #[error("oidc and oidc_secret_file must be set together")]
    IncompleteOidc,
    #[error("setting `{name}` has an invalid value `{value}`: {source}")]
    InvalidSetting {
        name: &'static str,
        value: String,
        #[source]
        source: BoxError,
    },
    #[error("setting `{name}` must be between {minimum} and {maximum}")]
    OutOfRange { name: &'static str, minimum: String, maximum: String },
    #[error("{file}: {source}")]
    InsecureFile {
        file: String,
        #[source]
        source: AuditError,
    },
    #[error("the reload engine is gone, the file watch cannot follow the module file")]
    EngineGone,
    #[error("file watch: {0}")]
    Watch(#[from] WatchError),
    #[error("plain HTTP is refused on {0}: configure tls_certificate and tls_key, or bind to a loopback address")]
    PlainHttpRefused(SocketAddr),
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("authentication: {0}")]
    Auth(#[from] AuthError),
    #[error("audit log: {0}")]
    Audit(#[from] AuditError),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("PEM file: {0}")]
    Pem(#[from] pem::Error),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("OpenAPI document: {0}")]
    Document(#[from] serde_json::Error),
}
