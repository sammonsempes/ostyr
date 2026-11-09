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
