use crate::rules::{MAX_FILE_BYTES, MAX_LABELS, MAX_RULES};
use core_config::error::ConfigError;
use core_pg::error::PgError;
use siem_schema::error::SchemaError;
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
    #[error("rule `{rule}`: {count} selector labels, at most {} allowed", MAX_LABELS)]
    TooManySelectors { rule: String, count: usize },
    #[error("evaluation time does not fit a timestamp")]
    Time(#[from] std::num::TryFromIntError),
    #[error("evaluation time out of range")]
    TimeOutOfRange,
    #[error("invalid tenant id")]
    InvalidTenant(#[source] PgError),
    #[error(transparent)]
    Schema(#[from] SchemaError),
}
