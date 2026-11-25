use crate::name::NameError;
use core_config::error::ConfigError;
use intel_feeds::config::FeedsError;
use intel_feeds::read::ReadError;
use ipnet::AddrParseError;
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::Utf8Error;
use thiserror::Error;
use time::OffsetDateTime;


#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("`{field}`: {source}")]
    Name {
        field: String,
        #[source]
        source: NameError,
    },
    #[error("`{field}` must be written in canonical form `{canonical}`")]
    NotCanonical { field: String, canonical: String },
    #[error("at least one name server is required")]
    NoNameServer,
    #[error("`{0}`: confidence above 100")]
    Confidence(String),
    #[error("`max_records` must be between 1 and {0}")]
    MaxRecords(usize),
    #[error("`{0}` is not an acceptable setting")]
    Setting(String),
    #[error("allowlist network `{value}`: {source}")]
    Network {
        value: String,
        #[source]
        source: AddrParseError,
    },
}


#[derive(Debug, Error)]
pub enum SerialError {
    #[error("serial counter file `{path}` is not a number: {source}")]
    Counter {
        path: PathBuf,
        #[source]
        source: ParseIntError,
    },
    #[error("serial counter file: {0}")]
    Open(#[source] ConfigError),
    #[error("serial counter file `{path}` refused: {reason}")]
    Refused { path: PathBuf, reason: String },
    #[error("serial counter file `{0}` is larger than allowed")]
    TooLarge(PathBuf),
    #[error("all 99 serials of the day are used, last was {0}")]
    Exhausted(u32),
    #[error("the clock {0} cannot be turned into a serial")]
    Clock(OffsetDateTime),
    #[error(transparent)]
    Io(#[from] io::Error),
}


#[derive(Debug, Error)]
pub enum RpzError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Serial(#[from] SerialError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
}


#[derive(Debug, Error)]
pub enum ReloadError {
    #[error("cannot run the Unbound control command: {0}")]
    Io(#[from] io::Error),
    #[error("the Unbound control command failed with status {0:?}")]
    Failed(Option<i32>),
    #[error("the Unbound control command did not finish within {0} seconds")]
    TimedOut(u64),
    #[error("the policy names another control program than the service runs")]
    Refused,
}


#[derive(Debug, Error)]
pub enum SourceError {
    #[error("the feeds file cannot be loaded")]
    Config(#[from] ConfigError),
    #[error("the feeds file is invalid")]
    Invalid(#[from] FeedsError),
    #[error("the feeds file has no `clickhouse` section")]
    Missing,
    #[error("the ClickHouse read failed")]
    Read(#[from] ReadError),
}


#[derive(Debug, Error)]
pub enum HostError {
    #[error("no Host header")]
    Missing,
    #[error("Host header too long")]
    TooLong,
    #[error("Host header is not UTF-8")]
    NotUtf8(#[from] Utf8Error),
    #[error("Host header port is not 1 to 5 digits")]
    BadPort,
    #[error("Host header name ends with a dot")]
    TrailingDot,
    #[error("Host header name ends with a number")]
    NumericName,
    #[error("Host header name is not a valid domain name")]
    InvalidName(#[from] NameError),
}


#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("usage: ostyr-dns-rpz <service.yaml>")]
    Usage,
    #[error("service file: {0}")]
    Settings(#[from] ConfigError),
    #[error("service file: invalid {0}")]
    Invalid(String),
    #[error("service file changed while the service started")]
    Changed,
    #[error("policy: {0}")]
    Policy(#[from] crate::policy::OpenError),
    #[error("audit file: {0}")]
    Audit(#[from] core_audit::error::AuditError),
    #[error("service file: {0} is read at start only, restart the service to change it")]
    Pinned(&'static str),
    #[error("watch: {0}")]
    Watch(#[from] core_config::error::WatchError),
    #[error(transparent)]
    Io(#[from] io::Error),
}
