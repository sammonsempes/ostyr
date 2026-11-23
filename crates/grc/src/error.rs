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
    #[error("unknown built-in framework {name:?}")]
    UnknownBuiltin { name: String },
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


#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Tenant(#[from] PgError),
    #[error("the report belongs to another tenant")]
    TenantMismatch,
    #[error("cannot render the report")]
    Render(#[source] GrcError),
    #[error("the report is {bytes} bytes, the limit is {max}")]
    TooLarge { bytes: usize, max: usize },
    #[error("the framework name is {bytes} bytes, the limit is {max}")]
    FrameworkTooLong { bytes: usize, max: usize },
    #[error("the tenant already holds {max} reports")]
    CapReached { max: i64 },
    #[error("the limit must be between 1 and {max}")]
    BadLimit { max: usize },
    #[error("the store failed")]
    Store(#[source] PgError),
    #[error("the store answered a row this version cannot read")]
    BadRow,
    #[error("the stored report no longer matches its digest")]
    DigestMismatch,
}
