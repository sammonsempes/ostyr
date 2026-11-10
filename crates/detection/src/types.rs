use crate::error::SinkError;
use crate::model::{AlertRecord, AlertStore};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use stream_correlation::engine::Engine;
use time::OffsetDateTime;


/// Commits the alerts of one batch under the subject tenant and returns how many were new; the store is the commit target's context.
pub type AlertSinkFn = fn(&AlertStore, &str, &[AlertRecord]) -> Result<usize, SinkError>;


pub type AlertWriter = Box<dyn Write + Send>;


pub type AlertSyncFn = Box<dyn Fn() -> io::Result<()> + Send>;


/// Starts a new alerts file after the full one was renamed away, returning the writer and the sync function of the new file.
pub type RotateFn = Box<dyn FnMut() -> io::Result<(AlertWriter, AlertSyncFn)> + Send>;


pub type SharedStopFn = dyn Fn() -> bool + Send + Sync;


pub type EngineMap = BTreeMap<String, Arc<Engine>>;


pub type ClockFn = fn() -> OffsetDateTime;


pub type SleepFn = fn(Duration);
