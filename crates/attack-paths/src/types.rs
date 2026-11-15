use crate::error::{GraphError, LimitsError, PathsError, TagsError};
use crate::model::{PathSet, Tags};
use petgraph::graph::DiGraph;


pub type GraphResult = Result<(), GraphError>;


pub type LimitsResult = Result<(), LimitsError>;


pub type TagsResult = Result<Tags, TagsError>;


pub type ApplyResult = Result<(), TagsError>;


pub type Search<'graph> = DiGraph<&'graph str, ()>;


pub type PathsResult = Result<PathSet, PathsError>;
