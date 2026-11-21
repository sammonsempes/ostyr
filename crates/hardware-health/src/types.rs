//! Type aliases.

use crate::model::{FailureClass, RunOutput, UpsSettings};
use std::path::Path;
use std::time::{Duration, Instant};


pub type RunnerFn = fn(&Path, &[&str], u64, Duration) -> Result<RunOutput, FailureClass>;


pub type ClockFn = fn(&Path) -> Instant;


pub type Context<'a> = ((&'a UpsSettings, &'a Path), (RunnerFn, ClockFn));
