//! Errors that refuse a whole smartctl output.

use thiserror::Error;


#[derive(Debug, Error)]
pub enum SmartError {
    #[error("reading the smartctl output failed")]
    Read(#[from] std::io::Error),
    #[error("smartctl output is larger than {limit} bytes")]
    Oversized { limit: u64 },
    #[error("smartctl output is not valid JSON ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("smartctl output is not a JSON object")]
    NotAnObject,
}


impl From<serde_json::Error> for SmartError {
    fn from(error: serde_json::Error) -> Self {
        Self::Malformed {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        }
    }
}
