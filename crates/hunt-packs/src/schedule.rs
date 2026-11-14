use crate::model::{HuntPack, Source};
use chrono::{DateTime, Datelike, Utc};
use thiserror::Error;


pub const MAX_DUE_RUNS: u32 = 24;


pub const MAX_GRACE_SECONDS: i64 = 3_600;


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9_999;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunWindow {
    pub start: i64,
    pub end: i64,
}


#[derive(Debug, Error)]
pub enum ScheduleError {
    #[error("at most {MAX_DUE_RUNS} runs can be requested")]
    TooManyRuns,
    #[error("the grace must be 0 to {MAX_GRACE_SECONDS} seconds")]
    InvalidGrace,
    #[error("a run time is outside the supported range")]
    OutOfRange,
}


/// Seconds as a year-checked unix time (years 0 to 9999).
pub fn checked_time(seconds: i64) -> Result<i64, ScheduleError> {
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .filter(|moment| (MIN_YEAR..=MAX_YEAR).contains(&moment.year()))
        .map(|_| seconds)
        .ok_or(ScheduleError::OutOfRange)
}


/// The window of the run ending at `end`.
pub fn window_for(end: i64, window_seconds: i64) -> Result<RunWindow, ScheduleError> {
    let start = end.checked_sub(window_seconds).ok_or(ScheduleError::OutOfRange)?;
    Ok(RunWindow {
        start: checked_time(start)?,
        end: checked_time(end)?,
    })
}


/// ClickHouse runs ending on multiples of `schedule_seconds` since the epoch, after `last_done_end` and at most `now - grace_seconds`.
pub fn due_runs(pack: &HuntPack, last_done_end: Option<i64>, now: i64, grace_seconds: i64, max_runs: u32) -> Result<Vec<RunWindow>, ScheduleError> {
    (max_runs <= MAX_DUE_RUNS).then_some(()).ok_or(ScheduleError::TooManyRuns)?;
    (0..=MAX_GRACE_SECONDS)
        .contains(&grace_seconds)
        .then_some(())
        .ok_or(ScheduleError::InvalidGrace)?;
    if pack.source == Source::Clickhouse {
        let step = i64::try_from(pack.schedule_seconds)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(ScheduleError::OutOfRange)?;
        let window = i64::try_from(pack.window_seconds).map_err(|_| ScheduleError::OutOfRange)?;
        let cutoff = now.checked_sub(grace_seconds).ok_or(ScheduleError::OutOfRange)?;
        let latest = cutoff.checked_sub(cutoff.rem_euclid(step)).ok_or(ScheduleError::OutOfRange)?;
        let first = match last_done_end {
            Some(done) => done.checked_add(step - done.rem_euclid(step)).ok_or(ScheduleError::OutOfRange)?,
            None => latest,
        };
        let ends: Vec<i64> = (0..max_runs)
            .map_while(|index| first.checked_add(step * i64::from(index)))
            .take_while(|end| *end <= latest)
            .collect();
        ends.into_iter().map(|end| window_for(end, window)).collect()
    } else {
        Ok(Vec::new())
    }
}
