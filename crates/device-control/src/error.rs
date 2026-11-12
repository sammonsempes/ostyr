use crate::limits::{MAX_REASON_CHARS, MAX_RULES};
use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("not exactly {length} lowercase hexadecimal digits")]
    Hex { length: usize },
    #[error("not a valid serial number")]
    Serial,
    #[error("not a valid owner")]
    Owner,
    #[error("reason longer than {MAX_REASON_CHARS} characters")]
    ReasonTooLong,
    #[error("reason holds a control, bidirectional, invisible, quote or backslash character")]
    ReasonForbidden,
    #[error("a rule needs at least one of class, vendor and product")]
    NoMatcher,
    #[error("a serial number is allowed on an allow rule only")]
    SerialOnBlock,
}


#[derive(Debug, Error)]
pub enum PolicyError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{path}: cannot open: {source}")]
    Open {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{file}: {count} rules and exceptions, more than {MAX_RULES}")]
    TooManyRules { file: String, count: usize },
}


#[derive(Debug, Error)]
pub enum RenderError {
    #[error("USBGuard has no audit mode: render only an enforce policy")]
    AuditMode,
}
