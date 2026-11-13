use crate::error::KeaError;
use crate::follow::{malformed_summary, poll, Counts, FollowState, Limits};
use crate::types::PauseFn;
use core_export::ecs::to_json;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::warn;


pub const FOLLOW_FLAG: &str = "--follow";


pub const POLL_INTERVAL: Duration = Duration::from_secs(1);


pub const COUNTS_EVERY_POLLS: u64 = 60;


pub const MAX_FOLLOW_POLLS: u64 = 1_000_000_000;


pub const MAX_ONE_SHOT_POLLS: u64 = 1_000_000;


/// The path and whether to keep following the file.
pub fn parse_args(args: &[&str]) -> Result<(PathBuf, bool), KeaError> {
    match args {
        [path] => Ok((PathBuf::from(path), false)),
        [path, FOLLOW_FLAG] => Ok((PathBuf::from(path), true)),
        _ => Err(KeaError::Usage),
    }
}


/// Used by a one-shot run, which has nothing to wait for.
pub fn no_pause(_interval: Duration) {}


/// The counts as one line, never any row content.
pub fn counts_line(counts: &Counts) -> String {
    format!(
        "processed={} duplicate={} evicted={} restarts={} absent={} refused={} recovered={} unrecovered={} beyond_seen={} malformed={}",
        counts.processed,
        counts.duplicate,
        counts.evicted,
        counts.restarts,
        counts.absent,
        counts.refused,
        counts.recovered,
        counts.unrecovered,
        counts.beyond_seen,
        malformed_summary(counts)
    )
}


fn poll_once(path: &Path, state: &mut FollowState, limits: &Limits, counts: &mut Counts, out: &mut dyn Write) -> Result<(), KeaError> {
    let mut events = Vec::new();
    match poll(path, state, limits, counts, &mut events) {
        Err(KeaError::NotRegular) => {
            counts.refused += 1;
            warn!("the lease path is not a regular file, refused");
        }
        other => other?,
    }
    events
        .iter()
        .try_for_each(|event| writeln!(out, "{}", to_json(event)?).map_err(KeaError::from))
}


/// Polls the file `polls` times, writing every new lease as one ECS JSON line and the counts on `err` every `COUNTS_EVERY_POLLS` polls; the follower starts now.
pub fn follow_file(path: &Path, polls: u64, out: &mut dyn Write, err: &mut dyn Write, pause: PauseFn) -> Result<Counts, KeaError> {
    follow_file_since(path, polls, (out, err), pause, OffsetDateTime::now_utc().unix_timestamp())
}


/// `follow_file` with the start time given (Unix seconds): a lease created at or after it that `.2` holds and the main file never showed is recovered.
pub fn follow_file_since(path: &Path, polls: u64, sinks: (&mut dyn Write, &mut dyn Write), pause: PauseFn, started: i64) -> Result<Counts, KeaError> {
    let (out, err) = sinks;
    let limits = Limits {
        started,
        ..Limits::default()
    };
    let mut state = FollowState::default();
    let mut counts = Counts::default();
    (1..=polls).try_for_each(|number| {
        poll_once(path, &mut state, &limits, &mut counts, out)?;
        if number % COUNTS_EVERY_POLLS == 0 {
            writeln!(err, "{}", counts_line(&counts))?;
        }
        pause(POLL_INTERVAL);
        Ok::<(), KeaError>(())
    })?;
    Ok(counts)
}


/// Writes the counts line (or the error) on `err`.
pub fn report(result: Result<Counts, KeaError>, err: &mut dyn Write) -> io::Result<ExitCode> {
    match result {
        Ok(counts) => {
            writeln!(err, "{}", counts_line(&counts))?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            writeln!(err, "{error}")?;
            Ok(ExitCode::FAILURE)
        }
    }
}


/// A one-shot run reads the whole file in polls of at most `MAX_LINES_PER_POLL` lines, and refuses a path that is not a regular file.
pub fn one_shot(path: &Path, out: &mut dyn Write, _err: &mut dyn Write) -> Result<Counts, KeaError> {
    let limits = Limits {
        started: OffsetDateTime::now_utc().unix_timestamp(),
        ..Limits::default()
    };
    let mut state = FollowState::default();
    let mut counts = Counts::default();
    (0..MAX_ONE_SHOT_POLLS).try_fold(false, |done, _| {
        if done {
            Ok::<bool, KeaError>(true)
        } else {
            let before = state.offset;
            poll_once(path, &mut state, &limits, &mut counts, out)?;
            Ok(state.offset == before)
        }
    })?;
    if counts.refused == 0 {
        Ok(counts)
    } else {
        Err(KeaError::NotRegular)
    }
}


/// `<csv> [--follow]`: ECS JSON lines on `out`, counts on `err`; `polls` bounds a follow and `pause` is called between its polls.
pub fn run(args: &[&str], out: &mut dyn Write, err: &mut dyn Write, polls: u64, pause: PauseFn) -> io::Result<ExitCode> {
    let result = match parse_args(args) {
        Ok((path, true)) => follow_file(&path, polls, out, err, pause),
        Ok((path, false)) => one_shot(&path, out, err),
        Err(error) => Err(error),
    };
    report(result, err)
}
