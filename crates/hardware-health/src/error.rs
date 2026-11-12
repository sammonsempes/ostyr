//! Errors that refuse a whole smartctl output.

use thiserror::Error;


#[derive(Debug, Error)]
pub enum SmartError {
    #[error("reading the smartctl output failed")]
    Read(#[from] std::io::Error),
    #[error("smartctl output is larger than {limit} bytes")]
    Oversized { limit: u64 },
    #[error("smartctl output is not valid JSON")]
    Malformed(#[from] serde_json::Error),
    #[error("smartctl output is not a JSON object")]
    NotAnObject,
}
