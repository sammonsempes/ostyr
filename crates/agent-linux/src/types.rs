use crate::error::CapabilityError;
use crate::error::IsolationError;
use crate::error::SensorError;
use crate::model::{CommandSpec, Failure, LinuxFile, OsquerySettings, Paths, SensorSettings, SourceSettings, UpdateSettings};
use arc_swap::ArcSwap;
use core_config::reload::ReloadEngine;
use parking_lot::Mutex;
use patch_inventory::model::Inventory;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;


pub type SharedSource = Arc<ArcSwap<SourceSettings>>;


/// A step run by a poll between the detection of a rotation and the drain of the old file; a test double injects a failure or a write there.
pub type StepFn = fn(&Paths);


/// Reads a file under a byte cap: `None` when absent, an error when larger than the cap; a test double injects a failure.
pub type ReadFn = fn(&Path, u64) -> Result<Option<Vec<u8>>, CapabilityError>;


pub type SharedSensor = Arc<ArcSwap<SensorSettings>>;


pub type RunFuture = Pin<Box<dyn Future<Output = Result<String, SensorError>> + Send>>;


/// Runs a program with arguments and returns its bounded standard output; a test double injects a canned answer.
pub type RunFn = fn(PathBuf, Vec<String>) -> RunFuture;


pub type KillFn = fn(rustix::process::Pid) -> rustix::io::Result<()>;


/// Held by every writer of the spool of this process (source, sensor, capabilities), so a call's lines are never interleaved with another's.
pub type SpoolLock = Arc<Mutex<()>>;


pub type NftFuture = Pin<Box<dyn Future<Output = Result<String, IsolationError>> + Send>>;


/// Runs `nft` with arguments and returns its bounded standard output; a test double injects a canned answer.
pub type NftFn = fn(PathBuf, Vec<String>) -> NftFuture;


/// Reads the file system statistics of a path; a test double injects a canned answer or a failure.
pub type StatFn = fn(&Path) -> rustix::io::Result<rustix::fs::StatVfs>;


pub type SharedUpdates = Arc<ArcSwap<UpdateSettings>>;


pub type SharedOsquery = Arc<ArcSwap<OsquerySettings>>;


/// A settings engine with the shared handles its subscriber keeps current.
pub type SettingsEngine = (ReloadEngine<LinuxFile>, SharedSource, SharedSensor, SharedUpdates, SharedOsquery);


pub type UpdateFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, SensorError>> + Send>>;


/// Runs one command under a deadline and returns its bounded standard output; a test double injects a canned answer.
pub type UpdateRunFn = fn(CommandSpec, Duration) -> UpdateFuture;


/// What an update run found: the inventory, or why it found nothing.
pub type Collected = Result<Inventory, Failure>;


/// Builds one osquery row from its raw JSON text, or refuses it; the counter lets a test see how many rows were built.
pub type RowBuilderFn = fn(&str, &mut usize) -> Option<BTreeMap<String, String>>;


/// Drops one mount of the private namespace (the production function runs `umount`); a test double injects a failure.
pub type ReleaseFn = fn(&std::path::Path) -> std::io::Result<()>;
