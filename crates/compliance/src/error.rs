use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ComplianceError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: {message}")]
    Invalid { file: String, message: String },
    #[error("tenant `{found}` does not match tenant `{expected}`")]
    TenantMismatch { expected: String, found: String },
    #[error("verdict for control `{control}` which is not in the baseline")]
    UnknownControl { control: String },
    #[error("query result is {bytes} bytes, over the limit")]
    ResultTooLarge { bytes: usize },
    #[error("query result has {rows} rows, over the limit")]
    TooManyRows { rows: usize },
    #[error("query result is unreadable: {0}")]
    UnreadableResult(#[from] serde_json::Error),
}
