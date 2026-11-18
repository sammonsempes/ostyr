//! Type aliases.

use crate::model::{FailureClass, RunOutput};
use std::path::Path;
use std::time::Duration;


pub type RunnerFn = fn(&Path, &[&str], u64, Duration) -> Result<RunOutput, FailureClass>;
