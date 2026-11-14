use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid tenant: {0}")]
    Tenant(#[source] PgError),
    #[error("the declared account id is not a valid reference")]
    Account,
    #[error("cannot read the document: {0}")]
    Read(#[source] std::io::Error),
    #[error("document is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("document is not a JSON array ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("document holds {count} findings, above the {max} limit")]
    TooManyFindings { count: usize, max: usize },
}
