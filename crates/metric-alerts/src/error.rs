use crate::rules::{MAX_FILE_BYTES, MAX_RULES};
use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum RuleError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: larger than {} bytes", MAX_FILE_BYTES)]
    FileTooLarge { file: String },
    #[error("{file}: {count} rules, at most {} allowed", MAX_RULES)]
    TooManyRules { file: String, count: usize },
    #[error("{file}: rule `{rule}`: invalid `{field}`")]
    Invalid { file: String, rule: String, field: &'static str },
    #[error("{file}: duplicate rule id `{rule}`")]
    DuplicateId { file: String, rule: String },
}
