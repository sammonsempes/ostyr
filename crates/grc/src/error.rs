use core_config::error::ConfigError;
use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum GrcError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: unreadable JSON ({category:?}) at line {line} column {column}")]
    Json {
        file: String,
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("{file}: {reason}")]
    Invalid { file: String, reason: String },
    #[error(transparent)]
    Tenant(#[from] PgError),
    #[error("an input belongs to another tenant")]
    TenantMismatch,
    #[error("an indicator or a control is given more than once")]
    Duplicate,
    #[error("the evidence digest does not match its fields")]
    EvidenceMismatch,
}
