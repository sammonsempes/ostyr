use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ParseError {
    #[error("cannot read the list: {0}")]
    Read(#[source] std::io::Error),
    #[error("list is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("list is not valid JSON ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("list kind is not {expected}")]
    WrongKind { expected: &'static str },
    #[error("list holds {count} items, above the {max} limit")]
    TooManyItems { count: usize, max: usize },
    #[error("the continue token is outside the allowed grammar")]
    BadContinue,
    #[error("the page run is not complete: it must end on a page without a continue token, within the page limit")]
    Incomplete,
    #[error("the page limits are above their ceilings")]
    BadPageLimits,
}


#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("invalid tenant: {0}")]
    Tenant(#[source] PgError),
    #[error("invalid cluster id: {0}")]
    Cluster(#[source] PgError),
    #[error("the two inventories are not of the same tenant and cluster")]
    ScopeMismatch,
}
