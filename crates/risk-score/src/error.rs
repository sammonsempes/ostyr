use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum RiskError {
    #[error("weights file: {0}")]
    Config(#[from] ConfigError),
    #[error("weight `{key}` is out of range")]
    OutOfRange { key: &'static str },
    #[error("more than {max} contributions")]
    TooManyContributions { max: usize },
    #[error("more than {max} distinct entities")]
    TooManyEntities { max: usize },
    #[error("entity id is empty, longer than {max} bytes or holds an unsafe character")]
    BadEntityId { max: usize },
    #[error("false positive rate is above one million per million")]
    RateOutOfRange,
    #[error("alerts store: {0}")]
    Store(#[from] alerts::error::StoreError),
}
