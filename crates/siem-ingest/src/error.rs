use crate::model::Message;
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


/// The refused message is handed back so the caller can retry it or leave it unacknowledged.
#[derive(Debug, Error)]
#[error("the buffer holds {buffered} of {cap} bytes, the message was refused")]
pub struct PushError {
    pub message: Message,
    pub buffered: usize,
    pub cap: usize,
}
