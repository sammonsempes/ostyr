use crate::error::CapabilityError;
use crate::model::{Paths, SourceSettings};
use arc_swap::ArcSwap;
use std::path::Path;
use std::sync::Arc;


pub type SharedSource = Arc<ArcSwap<SourceSettings>>;


/// A step run by a poll between the detection of a rotation and the drain of the old file; a test double injects a failure or a write there.
pub type StepFn = fn(&Paths);


/// Reads a file under a byte cap: `None` when absent, an error when larger than the cap; a test double injects a failure.
pub type ReadFn = fn(&Path, u64) -> Result<Option<Vec<u8>>, CapabilityError>;
