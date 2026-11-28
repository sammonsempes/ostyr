use ad_posture::error::SnapshotError;
use core_config::error::ConfigError;
use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum GraphError {
    #[error("{count} nodes, at most {max} are allowed")]
    TooManyNodes { count: usize, max: usize },
    #[error("{count} edges, at most {max} are allowed")]
    TooManyEdges { count: usize, max: usize },
    #[error("node {index}: the id is empty or longer than {max} bytes")]
    BadNodeId { index: usize, max: usize },
    #[error("node {index}: the id repeats an earlier node")]
    DuplicateNode { index: usize },
    #[error("edge {index}: it names a node that does not exist")]
    UnknownNode { index: usize },
}


#[derive(Debug, Error)]
pub enum LimitsError {
    #[error("max_depth {value} is outside 1 to {max}")]
    Depth { value: usize, max: usize },
    #[error("max_paths {value} is outside 1 to {max}")]
    Paths { value: usize, max: usize },
}


#[derive(Debug, Error)]
pub enum TagsError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{count} tags, at most {max} are allowed")]
    TooMany { count: usize, max: usize },
    #[error("tag {index}: it names a node that does not exist")]
    UnknownNode { index: usize },
    #[error("tag {index}: it names a DN that more than one entry holds, so the node cannot be told apart")]
    AmbiguousNode { index: usize },
    #[error("the tag file changed while it was read")]
    Changed,
    #[error("the tag file does not end with a `complete: sha256:` trailer line, so it may have been cut: run seal-tags")]
    Incomplete,
    #[error("the tag file changed after it was sealed: run seal-tags")]
    Altered,
    #[error("CR line endings: write the file with LF")]
    CarriageReturn,
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Tenant(#[from] PgError),
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error("cannot render the report")]
    Render(#[source] serde_json::Error),
    #[error("the report is at least {bytes} bytes, the limit is {max}")]
    TooLarge { bytes: usize, max: usize },
    #[error("the generation time is not a date-time RFC 3339 can write back in UTC (years 1 to 9999)")]
    BadGenerated,
    #[error("the tenant already holds {max} reports")]
    CapReached { max: i64 },
    #[error("the limit must be between 1 and {max}")]
    BadLimit { max: usize },
    #[error("the store failed")]
    Store(#[source] PgError),
    #[error("the store answered a row this version cannot read")]
    BadRow,
    #[error("the stored report no longer matches its digest")]
    DigestMismatch,
    #[error("the stored body is not a report document")]
    BadBody,
    #[error("the stored columns disagree with the stored body")]
    MetadataMismatch,
    #[error("the connection pool is full")]
    Busy,
}


#[derive(Debug, Error)]
pub enum SealError {
    #[error("usage: ostyr-attack-paths seal-tags [--reseal] <absolute file>")]
    Usage,
    #[error(transparent)]
    Tags(#[from] TagsError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("the file already ends with a `complete:` line: pass --reseal to seal it again")]
    AlreadySealed,
    #[error("the file does not end with a newline: it is sealed as read, so add the final newline first")]
    NoFinalNewline,
    #[error("the directory is not a directory, is group- or other-writable, or belongs to neither the caller nor root")]
    UnsafeDirectory,
    #[error("the file is group- or other-writable")]
    UnsafeFile,
    #[error("cannot read or write the file")]
    Io(#[from] std::io::Error),
}


#[derive(Debug, Error)]
pub enum PathsError {
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Limits(#[from] LimitsError),
}


/// Why one tenant produced no report in a round; the other tenants of the round still run.
#[derive(Debug, Error)]
pub enum TenantError {
    #[error(transparent)]
    File(#[from] ConfigError),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error("the snapshot is over its bound {bound}: {observed} observed, the limit is {limit}")]
    SnapshotBound { bound: &'static str, observed: u64, limit: u64 },
    #[error(transparent)]
    Tags(#[from] TagsError),
    #[error(transparent)]
    Paths(#[from] PathsError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the snapshot changed while it was read")]
    SnapshotChanged,
    #[error("the blocking task failed")]
    Join(#[from] tokio::task::JoinError),
}
