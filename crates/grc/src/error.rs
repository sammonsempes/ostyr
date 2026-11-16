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
    #[error("cannot write the CSV report")]
    Csv(#[from] csv::Error),
    #[error("cannot write the report")]
    Io(#[from] std::io::Error),
    #[error("cannot write the JSON report")]
    Serialize(#[from] serde_json::Error),
}
