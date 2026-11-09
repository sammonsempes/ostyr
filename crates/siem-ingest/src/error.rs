use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("`{field}` is {value}, outside {min}..={max}")]
    OutOfRange { field: &'static str, value: u64, min: u64, max: u64 },
    #[error("`{smaller}` ({smaller_value}) must not exceed `{larger}` ({larger_value})")]
    Inconsistent {
        smaller: &'static str,
        smaller_value: u64,
        larger: &'static str,
        larger_value: u64,
    },
    #[error("`{field}` is invalid: {reason}")]
    Invalid { field: &'static str, reason: &'static str },
}


#[derive(Debug, Error)]
pub enum IngestError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("invalid settings: {0}")]
    Settings(#[from] SettingsError),
}


/// The message stays with the caller: it flushes and pushes again, or leaves it unacknowledged for redelivery.
#[derive(Debug, Error)]
pub enum PushError {
    #[error("the buffer holds {buffered} of {cap} bytes, the message was refused")]
    BufferFull { buffered: usize, cap: usize },
    #[error("the open batch belongs to tenant `{open}`, flush it before pushing tenant `{incoming}`")]
    OtherTenant { open: String, incoming: String },
}


/// Refused before the batcher; the text never echoes the subject, which a peer chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TenantError {
    #[error("the subject does not follow the events subject layout")]
    Subject,
    #[error("the tenant token is empty")]
    Empty,
    #[error("the tenant token exceeds the length cap")]
    TooLong,
    #[error("the tenant token holds a character outside letters, digits, `-` and `_`")]
    Characters,
}


/// Fixed text per class: a ClickHouse message, which quotes the row, never reaches a log or a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertClass {
    ParseError,
    Unavailable,
    Timeout,
    Unauthorized,
    Rejected,
}


#[derive(Debug, Error)]
pub enum InsertError {
    #[error("ClickHouse insert failed: {0:?}")]
    Class(InsertClass),
    #[error("the ClickHouse password file could not be read")]
    Credentials(#[source] std::io::Error),
    #[error("the ClickHouse password file exceeds the size cap")]
    CredentialsTooLarge,
}


#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("fetching from the bus failed")]
    Fetch(#[source] core_config::types::BoxError),
}
