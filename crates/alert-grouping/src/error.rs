use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum GroupError {
    #[error("{count} alerts exceed the limit of {max}")]
    TooManyAlerts { count: usize, max: usize },
    #[error("more than {max} groups")]
    TooManyGroups { max: usize },
}


#[derive(Debug, Error)]
pub enum LimitsError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("`{field}` is {value}, outside {min} to {max}")]
    OutOfRange { field: &'static str, value: u64, min: u64, max: u64 },
}
