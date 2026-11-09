use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum StatusPageError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("input of another tenant than the page")]
    TenantMismatch,
    #[error("too many {what}: limit {limit}")]
    TooMany { what: &'static str, limit: usize },
    #[error("text `{field}` longer than {limit} bytes")]
    TextTooLong { field: &'static str, limit: usize },
    #[error("two components map to one service")]
    DuplicateService,
    #[error("{format} output larger than {limit} bytes")]
    OutputTooLarge { format: &'static str, limit: usize },
    #[error("page settings out of range: {0}")]
    InvalidSettings(String),
    #[error("snapshot of tenant `{snapshot}` refused by the page of tenant `{page}`")]
    SnapshotTenant { page: String, snapshot: String },
    #[error(transparent)]
    Audit(#[from] core_audit::error::AuditError),
    #[error(transparent)]
    Watch(#[from] core_config::error::WatchError),
    #[error("input or output failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot serialise the page: {0}")]
    Json(#[from] serde_json::Error),
}
