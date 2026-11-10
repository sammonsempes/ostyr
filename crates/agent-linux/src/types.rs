use crate::model::{Paths, SourceSettings};
use arc_swap::ArcSwap;
use std::sync::Arc;


pub type SharedSource = Arc<ArcSwap<SourceSettings>>;


/// A step run by a poll between the detection of a rotation and the drain of the old file; a test double injects a failure or a write there.
pub type StepFn = fn(&Paths);
