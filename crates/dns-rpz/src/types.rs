use crate::model::CommandStatus;
use crate::policy::Policy;
use core_config::reload::ReloadEngine;
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;


/// The reader and the byte length the source had when it was opened, when that is known.
pub type Opened = (Box<dyn BufRead>, Option<u64>);


pub type OpenFn<'a> = dyn Fn(OffsetDateTime) -> io::Result<Opened> + 'a;


/// Ends a command's process group; production passes `end_group`.
pub type GroupKillFn = fn(&mut std::process::Child) -> io::Result<()>;


pub type ClockFn<'a> = dyn Fn() -> OffsetDateTime + 'a;


pub type WaitFn<'a> = dyn Fn(Duration) -> bool + 'a;


pub type Counts = BTreeMap<&'static str, u64>;


pub type RunnerFn<'a> = dyn Fn(&str, &[String], Duration) -> io::Result<CommandStatus> + 'a;


pub type ConnectionOutcome = Result<Result<(), hyper::Error>, tokio::time::error::Elapsed>;


pub type PageResponse = hyper::Response<http_body_util::Full<bytes::Bytes>>;


pub type ReadbackFn<'a> = dyn Fn(&str, &[String], Duration) -> io::Result<String> + 'a;


/// Reads the engine's policy once per round; production passes `current_config`.
pub type SnapshotFn<'a> = dyn Fn(&ReloadEngine<Policy>) -> Arc<Policy> + 'a;
