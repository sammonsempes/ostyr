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
    #[error("device `{device}` appears more than once in the verdicts")]
    DuplicateDevice { device: String },
    #[error("device `{device}` has more than one verdict for control `{control}`")]
    DuplicateControl { device: String, control: String },
    #[error("query result is {bytes} bytes, over the limit")]
    ResultTooLarge { bytes: usize },
    #[error("query result has {rows} rows, over the limit")]
    TooManyRows { rows: usize },
    #[error("query result is unreadable: {0}")]
    UnreadableResult(#[from] serde_json::Error),
}


#[derive(Debug, Error)]
pub enum StateError {
    #[error("a run of {entries} entries is over the limit of {max}")]
    RunTooLarge { entries: usize, max: usize },
    #[error("the row cap is outside 0 to the per-tenant maximum")]
    CapOutOfRange,
    #[error("the time does not fit the state store")]
    TimeOutOfRange,
    #[error("the state store answered a row that cannot be read")]
    BadRow,
    #[error("the state store failed")]
    Store(#[source] core_pg::error::PgError),
}
