use crate::model::CommandStatus;
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::time::Duration;
use time::OffsetDateTime;


pub type OpenFn<'a> = dyn Fn(OffsetDateTime) -> io::Result<Box<dyn BufRead>> + 'a;


pub type ClockFn<'a> = dyn Fn() -> OffsetDateTime + 'a;


pub type Counts = BTreeMap<&'static str, u64>;


pub type RunnerFn<'a> = dyn Fn(&str, &[String], Duration) -> io::Result<CommandStatus> + 'a;


pub type ConnectionOutcome = Result<Result<(), hyper::Error>, tokio::time::error::Elapsed>;


pub type PageResponse = hyper::Response<http_body_util::Full<bytes::Bytes>>;
