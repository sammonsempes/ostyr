use core_config::error::ConfigError;
use core_pg::error::PgError;
use serde_json::error::Category;
use std::fmt;
use thiserror::Error;


/// No variant carries text taken from a listing.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("tenant refused: {0}")]
    Tenant(#[from] PgError),
    #[error("cannot read the listing: {0}")]
    Read(#[source] std::io::Error),
    #[error("listing is not valid JSON: {0}")]
    Json(JsonFailure),
    #[error("listing larger than {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("listing has more than {limit} snapshots")]
    TooManySnapshots { limit: usize },
    #[error("listing malformed: {what}")]
    Malformed { what: &'static str },
    #[error("declarations file refused: {0}")]
    Declarations(#[from] ConfigError),
    #[error("declarations refused: invalid {what}")]
    InvalidDeclarations { what: &'static str },
}


/// Where and why a listing failed to parse; serde's own message is dropped because it can echo listing text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonFailure {
    pub category: Category,
    pub line: usize,
    pub column: usize,
}


impl fmt::Display for JsonFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?} at line {} column {}", self.category, self.line, self.column)
    }
}


pub fn json_failure(error: serde_json::Error) -> BackupError {
    BackupError::Json(JsonFailure {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    })
}
