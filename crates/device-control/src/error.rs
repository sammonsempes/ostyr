use crate::limits::{MAX_EXTENSIONS, MAX_REASON_CHARS, MAX_RULES};
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
    #[error("a product needs its vendor: USBGuard refuses an id without one")]
    ProductWithoutVendor,
    #[error("a serial number is allowed on an allow rule only")]
    SerialOnBlock,
    #[error("not a valid Chromium extension id: exactly 32 characters a to p")]
    ChromiumId,
    #[error("not a valid Firefox extension id")]
    FirefoxId,
    #[error("not a valid update URL: https only, ASCII host and path, at most 2048 bytes")]
    UpdateUrl,
    #[error("a force entry needs an update_url")]
    UpdateUrlRequired,
    #[error("update_url is allowed on a force entry only")]
    UpdateUrlForbidden,
    #[error("duplicate extension for the same browser and id")]
    DuplicateExtension,
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
    #[error("{file}: {count} extensions, more than {MAX_EXTENSIONS}")]
    TooManyExtensions { file: String, count: usize },
    #[error("{file}: extension {index}: {source}")]
    Extension {
        file: String,
        index: usize,
        #[source]
        source: ValidationError,
    },
}


#[derive(Debug, Error)]
pub enum RenderError {
    #[error("no audit mode in a rule file or browser policy: render only an enforce policy")]
    AuditMode,
    #[error("{kind} {index} has no Windows equivalent ({reason}): the Windows agent cannot enforce it as the policy means it")]
    NoWindowsEquivalent {
        kind: &'static str,
        index: usize,
        reason: &'static str,
    },
}
