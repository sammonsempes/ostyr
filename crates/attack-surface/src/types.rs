use crate::error::{CommandError, ResultsError, ScopeError};
use crate::model::{Report, Scope};
use std::ffi::OsString;


pub type ScopeResult = Result<Scope, ScopeError>;


pub type ArgsResult = Result<Vec<OsString>, CommandError>;


pub type ReportResult = Result<Report, ResultsError>;
