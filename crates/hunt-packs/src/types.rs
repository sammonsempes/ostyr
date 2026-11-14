use crate::model::HuntPack;
use crate::run::{HuntOutcome, RunError};
use crate::schedule::{RunWindow, ScheduleError};


/// Runs one pack for one tenant on the window ending at the given unix second.
pub type RunFn<'run> = dyn FnMut(&HuntPack, &str, i64) -> Result<HuntOutcome, RunError> + 'run;


/// Same contract as `schedule::due_runs`: pack, last done end, now, grace, maximum runs.
pub type DueFn = fn(&HuntPack, Option<i64>, i64, i64, u32) -> Result<Vec<RunWindow>, ScheduleError>;
