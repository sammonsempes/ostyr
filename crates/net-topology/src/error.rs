use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ListError {
    #[error("not a JSON array: {0}")]
    Shape(#[source] serde_json::Error),
    #[error("list holds {count} entries, above the {max} limit")]
    TooMany { count: usize, max: usize },
}


#[derive(Debug, Error)]
pub enum ParseError {
    #[error("cannot read the report: {0}")]
    Read(#[source] std::io::Error),
    #[error("report is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("report is not the expected JSON ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("the {list} list holds {count} entries, above the {max} limit")]
    TooMany { list: &'static str, count: usize, max: usize },
    #[error("the local host name is not valid text")]
    InvalidHost,
}


#[derive(Debug, Error)]
pub enum LinkError {
    #[error("invalid tenant: {0}")]
    Tenant(#[source] PgError),
    #[error("the links are not all of one tenant")]
    TenantMismatch,
    #[error("stale_after_seconds {value} is outside 1..={max}")]
    InvalidStaleAfter { value: i64, max: i64 },
}
