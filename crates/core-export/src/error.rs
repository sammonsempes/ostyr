use crate::types::BoxError;
use std::io;
use thiserror::Error;


pub const USAGE: &str = "usage: webhook|syslog|otlp <config> <count> <first-sequence>";


#[derive(Debug, Error)]
pub enum ExportError {
    #[error("cannot serialise the event: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("cannot format a timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid certificate: {0}")]
    Certificate(#[source] ureq::Error),
    #[error("invalid server name `{name}`: {source}")]
    ServerName {
        name: String,
        #[source]
        source: rustls::pki_types::InvalidDnsNameError,
    },
    #[error("delivery failed after {attempts} attempt(s)")]
    Exhausted {
        attempts: u32,
        #[source]
        source: Option<BoxError>,
    },
    #[error("cannot resolve the secret reference: {0}")]
    Secret(#[source] BoxError),
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error("the token file {path} is larger than {max} bytes")]
    TokenTooLarge { path: String, max: usize },
    #[error("the token file {0} is empty")]
    TokenEmpty(String),
    #[error("invalid OTLP setting: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Audit(#[from] core_audit::error::AuditError),
    #[error("{USAGE}")]
    Usage,
    #[error("the configuration has no `{0}` output")]
    MissingSection(&'static str),
}
