use crate::api_model::{FindingsQuery, FindingsReply};
use crate::clock::Reading;
use crate::error::FindingsError;
use crate::model::HuntPack;
use crate::run::{HuntOutcome, RunError};
use crate::schedule::{RunWindow, ScheduleError};
use crate::store::FindingRow;
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;


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


pub type FindingsFuture = Pin<Box<dyn Future<Output = Result<FindingsReply, FindingsError>> + Send>>;


/// Reads one page of the tenant's findings: injected, so a test serves the route from memory and the example from PostgreSQL.
pub type FindingsFn = Arc<dyn Fn(TenantScope, FindingsQuery) -> FindingsFuture + Send + Sync>;


/// Resolves when the process is told to stop (SIGINT and SIGTERM in production).
pub type InterruptWait = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
