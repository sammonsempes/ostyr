use crate::error::{CommandError, ResultsError, RunError, ScopeError};
use crate::model::{Found, Report, ScanReport, Scope, TargetReport};
use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;


pub type ScopeResult = Result<Scope, ScopeError>;


pub type ArgsResult = Result<Vec<OsString>, CommandError>;


pub type ReportResult = Result<Report, ResultsError>;


pub type ScanResult = Result<ScanReport, RunError>;


pub type ResolveFn = fn(Option<SocketAddr>, &str, Duration, usize) -> io::Result<Vec<IpAddr>>;


pub type Executed = (TargetReport, Vec<Found>, bool);
