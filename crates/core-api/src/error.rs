use core_audit::error::AuditError;
use core_auth::error::AuthError;
use core_config::error::ConfigError;
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
