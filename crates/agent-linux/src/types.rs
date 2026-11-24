use crate::error::CapabilityError;
use crate::error::IsolationError;
use crate::error::SensorError;
use crate::model::{
    CommandSpec, ExecProbeSettings, Failure, LinuxFile, MetricsSettings, OsquerySettings, Paths, SensorSettings, SourceSettings, UpdateSettings,
};
use arc_swap::ArcSwap;
use core_config::reload::ReloadEngine;
#[cfg(target_os = "linux")]
use ebpf_probes::drain::Drained;
#[cfg(target_os = "linux")]
use ebpf_probes::error::LoadError;
use parking_lot::Mutex;
use patch_inventory::model::Inventory;
use std::collections::BTreeMap;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;


pub type SharedSource = Arc<ArcSwap<SourceSettings>>;


/// A step run by a poll between the detection of a rotation and the drain of the old file; a test double injects a failure or a write there.
pub type StepFn = fn(&Paths);


/// Reads a file under a byte cap: `None` when absent, an error when larger than the cap; a test double injects a failure.
pub type ReadFn = fn(&Path, u64) -> Result<Option<Vec<u8>>, CapabilityError>;


/// A step run between the anchor and the reopen of a regular file, given the directory handle and the name; a test double swaps the name there.
pub type NameSwapFn = fn(&OwnedFd, &str);


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


pub type SharedMetrics = Arc<ArcSwap<MetricsSettings>>;


pub type SharedExecProbe = Arc<ArcSwap<ExecProbeSettings>>;


/// What the probe thread returns: the polls it made, or the fixed reason it never ran.
#[cfg(target_os = "linux")]
pub type ProbeResult = Result<u32, LoadError>;


/// Loads the probe, calls the first closure once attached and polls until the flag is set (production: `ebpf_probes::loader::run_exec_probe` when built with `ebpf`, else `not_built`); a test double injects any outcome.
#[cfg(target_os = "linux")]
pub type ProbeFn = fn(&AtomicBool, u32, &mut dyn FnMut(), &mut dyn FnMut(Drained)) -> ProbeResult;


#[cfg(target_os = "linux")]
pub type ProbeJob = Box<dyn FnOnce() -> ProbeResult + Send>;


/// Realtime minus monotonic nanoseconds; a test double injects any offset.
#[cfg(target_os = "linux")]
pub type OffsetFn = fn() -> i128;


/// Monotonic seconds; a test double injects any clock.
#[cfg(target_os = "linux")]
pub type MonotonicFn = fn() -> u64;


/// Starts the probe thread (production: `exec_probe::spawn_thread`); a test double injects a refusal.
#[cfg(target_os = "linux")]
pub type SpawnFn = fn(ProbeJob) -> std::io::Result<JoinHandle<ProbeResult>>;


/// A settings engine with the shared handles its subscriber keeps current.
pub type SettingsEngine = (
    ReloadEngine<LinuxFile>,
    SharedSource,
    SharedSensor,
    SharedUpdates,
    SharedOsquery,
    SharedMetrics,
    SharedExecProbe,
);


pub type UpdateFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, SensorError>> + Send>>;


/// Runs one command under a deadline and returns its bounded standard output; a test double injects a canned answer.
pub type UpdateRunFn = fn(CommandSpec, Duration) -> UpdateFuture;


/// What an update run found: the inventory, or why it found nothing.
pub type Collected = Result<Inventory, Failure>;


/// Builds one osquery row from its raw JSON text, or refuses it; the counter lets a test see how many rows were built.
pub type RowBuilderFn = fn(&str, &mut usize) -> Option<BTreeMap<String, String>>;


/// Drops one mount of the private namespace (the production function runs `umount`); a test double injects a failure.
pub type ReleaseFn = fn(&std::path::Path) -> std::io::Result<()>;


pub type ChildKillFn = fn(&mut std::process::Child) -> std::io::Result<()>;


/// Reads a regular file under a byte cap (production: `trusted::read_trusted_capped`); a test double injects bytes or a failure.
pub type ReadBytesFn = fn(&std::path::Path, u64) -> Result<Vec<u8>, core_config::error::ConfigError>;


/// Judges an opened FIM input from its facts: regular file, mode, owner, the agent's user; a refusal is a fixed reason.
pub type JudgeFn = fn(bool, u32, u32, u32) -> Result<(), &'static str>;


/// Runs between the open of a FIM input and its judgement; production does nothing, a test swaps the path there.
pub type AfterOpenFn = fn(&std::path::Path);


/// Reads the metadata of an opened switch handle; a test double injects a failure.
pub type InspectFn = fn(&std::fs::File) -> std::io::Result<std::fs::Metadata>;
