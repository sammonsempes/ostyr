use crate::error::{GraphError, LimitsError, PathsError, TagsError};
use crate::model::{PathSet, Tags};


pub type GraphResult = Result<(), GraphError>;


pub type LimitsResult = Result<(), LimitsError>;


pub type TagsResult = Result<Tags, TagsError>;


pub type ApplyResult = Result<(), TagsError>;


pub type PathsResult = Result<PathSet, PathsError>;
