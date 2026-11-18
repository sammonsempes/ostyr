//! Type aliases.

use crate::model::{FailureClass, RunOutput, SmartSettings};
use std::path::Path;
use std::time::{Duration, Instant};


pub type RunnerFn = fn(&Path, &[&str], u64, Duration) -> Result<RunOutput, FailureClass>;


pub type ClockFn = fn(&SmartSettings) -> Instant;
