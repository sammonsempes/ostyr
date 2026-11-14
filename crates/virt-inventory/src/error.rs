use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ParseError {
    #[error("cannot read the answer: {0}")]
    Read(#[source] std::io::Error),
    #[error("answer is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("answer is not valid JSON ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("answer holds {count} entries, above the {max} limit")]
    TooManyItems { count: usize, max: usize },
    #[error("a path holds {count} privileges, above the {max} limit")]
    TooManyPrivileges { count: usize, max: usize },
    #[error("the permissions hold {count} grants, above the {max} limit")]
    TooManyGrants { count: usize, max: usize },
    #[error("a permission path, privilege name or flag is refused")]
    BadPermission,
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


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReadOnlyError {
    #[error("the token holds no privilege at all")]
    NoRights,
    #[error("the token holds privileges beyond the read-only set: {privileges:?} ({omitted} more)")]
    HasWriteRights { privileges: Vec<String>, omitted: usize },
}
