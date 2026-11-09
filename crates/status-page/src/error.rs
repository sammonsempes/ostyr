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
    #[error("cannot serialise the page: {0}")]
    Json(#[from] serde_json::Error),
}
