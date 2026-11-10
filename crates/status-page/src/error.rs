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
    #[error("invalid rule for service `{service}`: {reason}")]
    InvalidRule { service: String, reason: &'static str },
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


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("text `{field}` longer than {limit} characters")]
    TextTooLong { field: &'static str, limit: usize },
    #[error("text `{field}` is empty or holds a control character")]
    TextInvalid { field: &'static str },
    #[error("limit {limit} is outside 1..={max}")]
    LimitOutOfRange { limit: u32, max: u32 },
    #[error("no such incident for this tenant, a stale version, or the update limit is reached")]
    Conflict,
    #[error("unexpected value in column `{column}`")]
    BadRow { column: &'static str },
    #[error(transparent)]
    Pg(#[from] core_pg::error::PgError),
}
