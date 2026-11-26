use crate::settings::{MAX_BYTES_CAP, MAX_TIMEOUT_MS, MAX_URL_BYTES, MIN_TIMEOUT_MS};
use core_config::error::ConfigError;
use core_pg::error::PgError;
use siem_ingest::error::{InsertClass, InsertError};
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


/// Every text is fixed: the token, a body and the server's message never reach an error.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("api_url must be https with a host, no userinfo, query, fragment or path, at most {MAX_URL_BYTES} bytes")]
    Url,
    #[error("timeout_ms must be within {MIN_TIMEOUT_MS}..={MAX_TIMEOUT_MS}")]
    Timeout,
    #[error("limits.max_bytes must be within 1..={MAX_BYTES_CAP}")]
    MaxBytes,
    #[error(transparent)]
    Scope(#[from] InventoryError),
    #[error("the CA file could not be used")]
    CaFile(#[source] ConfigError),
    #[error("the token file could not be used")]
    TokenFile(#[source] PgError),
    #[error("the token must be user@realm!tokenid=secret in ASCII letters, digits and @!=._-")]
    TokenShape,
    #[error(transparent)]
    Agent(#[from] InsertError),
    #[error("the request failed: {0:?}")]
    Transport(InsertClass),
    #[error("the server certificate or the TLS handshake was refused")]
    Certificate,
    #[error("the server answered status {0}")]
    Status(u16),
    #[error("the answer body could not be read")]
    Body(#[source] std::io::Error),
    #[error("the answer is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("the permissions answer is refused: {0}")]
    Permissions(#[source] ParseError),
    #[error("the resources answer is refused: {0}")]
    Resources(#[source] ParseError),
    #[error("the token is not read-only: {0}")]
    WritableCredential(#[source] ReadOnlyError),
}


#[derive(Debug, Error)]
pub enum SyncError {
    #[error("invalid tenant: {0}")]
    Tenant(#[source] PgError),
    #[error("invalid cluster id: {0}")]
    Cluster(#[source] PgError),
    #[error("the {field} of a resource is not a plain identifier")]
    BadIdentity { field: &'static str },
    #[error("cmdb store: {0}")]
    Store(#[from] cmdb::error::StoreError),
}


#[derive(Debug, Error)]
pub enum RoundError {
    #[error("proxmox fetch refused: {0}")]
    Fetch(#[from] FetchError),
    #[error("the cmdb store is unreachable: {0}")]
    Pg(#[from] PgError),
    #[error("cmdb sync failed: {0}")]
    Sync(#[from] SyncError),
}


#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("usage: ostyr-virt-inventory <settings.yaml>")]
    Usage,
    #[error("interval_seconds must be within {min}..={max}")]
    Interval { min: u64, max: u64 },
    #[error("max_assets must be within 1..={max}")]
    MaxAssets { max: usize },
    #[error("max_child_rows must be within 1..={max}")]
    MaxChildRows { max: usize },
}
