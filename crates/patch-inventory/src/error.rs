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
