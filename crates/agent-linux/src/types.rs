use crate::error::CapabilityError;
use crate::error::SensorError;
use crate::model::{Paths, SensorSettings, SourceSettings};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;


pub type SharedSource = Arc<ArcSwap<SourceSettings>>;


/// A step run by a poll between the detection of a rotation and the drain of the old file; a test double injects a failure or a write there.
pub type StepFn = fn(&Paths);


/// Reads a file under a byte cap: `None` when absent, an error when larger than the cap; a test double injects a failure.
pub type ReadFn = fn(&Path, u64) -> Result<Option<Vec<u8>>, CapabilityError>;


pub type SharedSensor = Arc<ArcSwap<SensorSettings>>;


pub type RunFuture = Pin<Box<dyn Future<Output = Result<String, SensorError>> + Send>>;


/// Runs a program with arguments and returns its bounded standard output; a test double injects a canned answer.
pub type RunFn = fn(PathBuf, Vec<String>) -> RunFuture;


/// Held by every writer of the spool of this process (source, sensor, capabilities), so a call's lines are never interleaved with another's.
pub type SpoolLock = Arc<Mutex<()>>;
