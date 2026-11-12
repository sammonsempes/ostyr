use core_config::error::ConfigError;
use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum GrcError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: unreadable JSON")]
    Json {
        file: String,
        #[source]
        source: serde_json::Error,
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
