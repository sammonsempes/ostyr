//! Error types.

use crate::model::Family;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum VersionError {
    #[error("unsupported ecosystem {0}")]
    UnknownEcosystem(String),
    #[error("unparsable {family:?} version {text}")]
    Unparsable { family: Family, text: String },
}


#[derive(Debug, Error)]
pub enum OsvError {
    #[error("record of {size} bytes exceeds the limit of {max}")]
    TooLarge { size: usize, max: usize },
    #[error("{what}: {count} exceeds the limit of {max}")]
    TooMany { what: &'static str, count: usize, max: usize },
    #[error("invalid OSV JSON")]
    Json(#[from] serde_json::Error),
}


#[derive(Debug, Error)]
pub enum EolError {
    #[error("end-of-life table: {count} entries exceed the limit of {max}")]
    TooMany { count: usize, max: usize },
    #[error("end-of-life table: {0}")]
    Config(#[from] core_config::error::ConfigError),
}
