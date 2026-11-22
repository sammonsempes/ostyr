//! Errors that refuse a whole input.

use thiserror::Error;


#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("reading the package manager output failed")]
    Read(#[from] std::io::Error),
    #[error("input is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("input has more than {limit} lines")]
    TooManyLines { limit: usize },
}


#[derive(Debug, Error)]
pub enum WindowsError {
    #[error("reading the update search output failed")]
    Input(#[from] InventoryError),
    #[error("the update search output holds a byte outside printable ASCII")]
    NotAscii,
    #[error("the update search printed nothing")]
    NoOutput,
    #[error("the update search output is not the expected JSON envelope (line {line}, column {column})")]
    Malformed { line: usize, column: usize },
    #[error("the update search failed with result code {code}")]
    SearchFailed { code: i64 },
    #[error("the update search lists more than {limit} updates")]
    TooManyUpdates { limit: usize },
}
