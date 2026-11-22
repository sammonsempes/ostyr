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
    #[error("cannot reserve {limit} bytes for a listing")]
    Reservation {
        limit: u64,
        #[source]
        source: std::collections::TryReserveError,
    },
    #[error("listing has more than {limit} snapshots")]
    TooManySnapshots { limit: usize },
    #[error("listing malformed: {what}")]
    Malformed { what: &'static str },
    #[error("declarations file refused: {0}")]
    Declarations(#[from] ConfigError),
    #[error("declarations refused: invalid {what}")]
    InvalidDeclarations { what: &'static str },
}


/// No variant carries text taken from a listing or the database.
#[derive(Debug, Error)]
pub enum RestoreStoreError {
    #[error("{count} restore tests declared, over the limit of {max}")]
    RowCap { tenant: String, count: u64, max: u64 },
    #[error("the row cap is outside 0 to the per-tenant maximum")]
    CapOutOfRange,
    #[error("a declared restore test key is outside the grammar")]
    InvalidKey,
    #[error("a result belongs to another tenant")]
    TenantMismatch,
    #[error("a result names a test that is not declared")]
    UndeclaredResult,
    #[error("two results name the same test")]
    DuplicateResult,
    #[error("a result is dated more than {max} seconds after the database clock")]
    ClockSkew { max: u64 },
    #[error("the restore store answered a row that cannot be read")]
    BadRow,
    #[error("the restore store failed")]
    Store(#[source] PgError),
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
