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
}


#[derive(Debug, Error)]
pub enum PathsError {
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Limits(#[from] LimitsError),
}
