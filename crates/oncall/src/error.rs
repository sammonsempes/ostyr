use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum OncallError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: larger than {max} bytes")]
    FileTooLarge { file: String, max: u64 },
    #[error("{what}: {value} is outside {min}..={max}")]
    OutOfBounds { what: &'static str, value: u64, min: u64, max: u64 },
    #[error("override of `{person}` ends before it starts")]
    OverrideRange { person: String },
}
