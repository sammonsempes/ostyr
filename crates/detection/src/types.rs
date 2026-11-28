use crate::error::{CursorError, RetroError, SinkError};
use crate::model::{AlertRecord, AlertStore};
use crate::retro::{RetroOutcome, RetroQuery, RetroReply, RetroRequest};
use crate::retro_cursor::RetroCursors;
use siem_ingest::error::InsertClass;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;
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


/// Moves a file; injected so a test can fail one step of a rotation.
pub type RenameFn = fn(&Path, &Path) -> io::Result<()>;


pub type SharedStopFn = dyn Fn() -> bool + Send + Sync;


pub type EngineMap = BTreeMap<String, Arc<Engine>>;


pub type ClockFn = fn() -> OffsetDateTime;


pub type SleepFn = fn(Duration);


/// Microseconds since the Unix epoch, injected so a test fixes the `created` time of an alert.
pub type MicrosFn = fn() -> u64;


/// Flushes the directory holding a file; injected so a test can see the order of a rotation.
pub type SyncDirFn = fn(&Path) -> io::Result<()>;


/// Records refused as permanent errors, per kind of refusal.
pub type KindCounts = BTreeMap<String, u64>;


/// Raised by SIGINT and SIGTERM, read by the loop between two cycles.
pub type StopFlag = Arc<AtomicBool>;


/// One request to the reader; a transport failure is already a fixed class.
pub type RetroSendFn<'a> = dyn Fn(&RetroRequest) -> Result<RetroReply, InsertClass> + 'a;


/// The time spent since the run began, injected so a test freezes it.
pub type ElapsedFn<'a> = dyn Fn() -> Duration + 'a;


/// Reads one window of one rule; the real one is `run_retro` over the settings and the mapping.
pub type RetroReadFn<'a> = dyn Fn(&RetroQuery) -> Result<RetroOutcome, RetroError> + 'a;


/// Stores alerts under the tenant; the real one is `commit_pg`.
pub type RetroInsertFn<'a> = dyn Fn(&str, &[AlertRecord]) -> Result<usize, SinkError> + 'a;


/// Saves the whole cursor document atomically.
pub type RetroSaveFn<'a> = dyn Fn(&RetroCursors) -> Result<(), CursorError> + 'a;


/// Syncs a file to disk; injected so a test can fail it.
pub type FileSyncFn = fn(&std::fs::File) -> io::Result<()>;
