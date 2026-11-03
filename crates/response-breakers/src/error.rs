use core_audit::error::AuditError;
use core_config::error::ConfigError;
use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("counter file is not valid: {0}")]
    Json(#[from] serde_json::Error),
}


#[derive(Debug, Error)]
pub enum BreakerError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot audit, nothing recorded: {0}")]
    Audit(#[from] AuditError),
    #[error("the override would already be expired")]
    AlreadyExpired,
}


#[derive(Debug, Error)]
pub enum CommandError {
    #[error("usage: {0}")]
    Usage(&'static str),
    #[error("not a number: {0}")]
    Number(#[from] ParseIntError),
    #[error("not an address: {0}")]
    Address(#[from] AddrParseError),
    #[error("unknown limit `{0}`")]
    Limit(String),
    #[error(transparent)]
    Breaker(#[from] BreakerError),
}
