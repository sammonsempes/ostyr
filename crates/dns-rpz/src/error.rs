use crate::name::NameError;
use ipnet::AddrParseError;
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
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
}
