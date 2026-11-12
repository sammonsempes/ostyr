//! Errors that refuse a whole tool output or a threshold file.

use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum NtpError {
    #[error("reading the tool output failed")]
    Read(#[from] std::io::Error),
    #[error("tool output is larger than {limit} bytes")]
    Oversized { limit: u64 },
    #[error("tool output is not valid UTF-8")]
    NotUtf8(#[from] std::string::FromUtf8Error),
    #[error("tool output is malformed: {reason}")]
    Malformed { reason: &'static str },
    #[error("thresholds file is invalid")]
    Config(#[from] ConfigError),
    #[error("threshold {field} is out of range")]
    OutOfRange { field: &'static str },
}
