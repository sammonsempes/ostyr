use std::str::Utf8Error;
use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("the global rate must be above zero")]
    ZeroRate,
    #[error("the global burst must be above zero")]
    ZeroBurst,
    #[error("the per-source share must be between 1 and 100 percent")]
    BadShare,
    #[error("the number of tracked sources must be above zero")]
    ZeroMaxSources,
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("the message is not valid UTF-8")]
    NotUtf8(#[from] Utf8Error),
    #[error("the message is neither RFC 5424 nor RFC 3164")]
    Malformed,
    #[error("the message carries no priority")]
    MissingPriority,
    #[error("the {0} field is too long")]
    FieldTooLong(&'static str),
    #[error("the structured data exceeds its bounds")]
    TooMuchStructuredData,
}
