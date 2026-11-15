use core_config::error::ConfigError;
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
}


#[derive(Debug, Error)]
pub enum PathsError {
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Limits(#[from] LimitsError),
}
