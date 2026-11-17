use crate::clock::Reading;
use crate::model::HuntPack;
use crate::run::{HuntOutcome, RunError};
use crate::schedule::{RunWindow, ScheduleError};
use crate::store::FindingRow;
use core_pg::error::PgError;
use std::future::Future;
use std::pin::Pin;


/// Runs one pack for one tenant on the window ending at the given unix second.
pub type RunFn<'run> = dyn FnMut(&HuntPack, &str, i64) -> Result<HuntOutcome, RunError> + 'run;


/// Same contract as `schedule::due_runs`: pack, last done end, now, grace, maximum runs.
pub type DueFn = fn(&HuntPack, Option<i64>, i64, i64, u32) -> Result<Vec<RunWindow>, ScheduleError>;


/// The wall and monotonic clocks, read together.
pub type ClockFn<'clock> = dyn FnMut() -> Reading + 'clock;


pub type SleepFuture = Pin<Box<dyn Future<Output = ()>>>;


/// Sleeps for the given number of seconds.
pub type SleepFn<'sleep> = dyn FnMut(u64) -> SleepFuture + 'sleep;


/// The answer of the findings list executor, which returns rows rather than one integer column.
pub type ListResult = Result<Vec<FindingRow>, PgError>;
