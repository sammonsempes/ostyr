use crate::error::{CommandError, ResultsError, RunError, ScopeError};
use crate::model::{Report, ScanReport, Scope};
use std::ffi::OsString;


pub type ScopeResult = Result<Scope, ScopeError>;


pub type ArgsResult = Result<Vec<OsString>, CommandError>;


pub type ReportResult = Result<Report, ResultsError>;


pub type ScanResult = Result<ScanReport, RunError>;
