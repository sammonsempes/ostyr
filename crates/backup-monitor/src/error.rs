use core_config::error::ConfigError;
use core_pg::error::PgError;
use thiserror::Error;


/// No variant carries text taken from a listing.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("tenant refused: {0}")]
    Tenant(#[from] PgError),
    #[error("cannot read the listing: {0}")]
    Read(#[source] std::io::Error),
    #[error("listing is not valid JSON: {0}")]
    Json(#[source] serde_json::Error),
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
