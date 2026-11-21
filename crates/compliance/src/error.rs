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


#[derive(Debug, Error)]
pub enum ReportError {
    #[error("the report could not be written")]
    Write(#[from] std::io::Error),
    #[error("state_full alert not raised: {category}")]
    AlertFailed {
        category: &'static str,
        #[source]
        source: alerts::error::StoreError,
    },
}


#[derive(Debug, Error)]
pub enum ReadError {
    #[error("database: {0}")]
    Pg(#[from] core_pg::error::PgError),
    #[error("connection: {0}")]
    Lease(#[from] alerts::error::StoreError),
    #[error("a limit does not fit the statement")]
    BadLimit,
    #[error("page size must be between 1 and {limit}")]
    BadPageSize { limit: usize },
    #[error("cursor is malformed")]
    BadCursor,
    #[error("verdict is not one of fail, error, excepted, pass or all")]
    BadVerdict,
    #[error("baseline is not a valid baseline name")]
    BadBaseline,
    #[error("a stored key is outside the grammar")]
    BadKey,
    #[error("the store returned a row that cannot be read")]
    BadRow,
    #[error("a stored time cannot be written as an RFC 3339 date")]
    Unrepresentable,
}


#[derive(Debug, Error)]
pub enum IndicatorError {
    #[error("more than {max} baselines")]
    TooManyBaselines { max: usize },
    #[error("a baseline belongs to another tenant than the scope")]
    TenantMismatch,
    #[error("a baseline name is given twice")]
    DuplicateBaseline,
    #[error("the time does not fit the indicator")]
    TimeOutOfRange,
    #[error("the state store answered a row that cannot be read")]
    BadRow,
    #[error("the computed value is not a number between 0 and 1")]
    ValueOutOfRange,
    #[error("the state store failed")]
    Store(#[source] core_pg::error::PgError),
    #[error("the output could not be written")]
    Write(#[from] std::io::Error),
}
