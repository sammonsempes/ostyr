use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ListError {
    #[error("not a JSON array ({category:?}) at line {line} column {column}")]
    Shape {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
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
    #[error("{count} observations are not of the requested local port")]
    WrongPort { count: usize },
    #[error("max_port_bytes {per_port} is above max_bytes {per_host}")]
    InvalidPortBytes { per_port: u64, per_host: u64 },
    #[error("max_host_read_bytes {budget} is below max_port_bytes {per_port} or above {ceiling}")]
    InvalidHostBytes { budget: u64, per_port: u64, ceiling: u64 },
    #[error("the local port name is not a valid interface name")]
    InvalidPort,
    #[error("the local host name is not valid text")]
    InvalidHost,
    #[error("max_links_per_port {per_port} is above max_links_per_host {per_host}")]
    InvalidLimits { per_port: usize, per_host: usize },
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
