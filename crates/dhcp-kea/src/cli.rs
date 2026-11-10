use crate::error::KeaError;
use crate::follow::{malformed_summary, poll, Counts, FollowState, Limits};
use crate::types::PauseFn;
use core_export::ecs::to_json;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;


pub const FOLLOW_FLAG: &str = "--follow";


pub const POLL_INTERVAL: Duration = Duration::from_secs(1);


pub const MAX_FOLLOW_POLLS: u64 = 1_000_000_000;


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


/// Polls the file `polls` times, writing every new lease as one ECS JSON line and calling `pause` between polls.
pub fn follow_file(path: &Path, polls: u64, out: &mut dyn Write, pause: PauseFn) -> Result<Counts, KeaError> {
    let mut state = FollowState::default();
    let mut counts = Counts::default();
    (0..polls).try_for_each(|_| {
        let mut events = Vec::new();
        poll(path, &mut state, &Limits::default(), &mut counts, &mut events)?;
        events
            .iter()
            .try_for_each(|event| writeln!(out, "{}", to_json(event)?).map_err(KeaError::from))?;
        pause(POLL_INTERVAL);
        Ok::<(), KeaError>(())
    })?;
    Ok(counts)
}


/// Writes the counts line (or the error) on `err`.
pub fn report(result: Result<Counts, KeaError>, err: &mut dyn Write) -> io::Result<ExitCode> {
    match result {
        Ok(counts) => {
            writeln!(
                err,
                "processed={} duplicate={} evicted={} restarts={} absent={} malformed={}",
                counts.processed,
                counts.duplicate,
                counts.evicted,
                counts.restarts,
                counts.absent,
                malformed_summary(&counts)
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            writeln!(err, "{error}")?;
            Ok(ExitCode::FAILURE)
        }
    }
}


/// `<csv> [--follow]`: ECS JSON lines on `out`, counts on `err`; `polls` bounds a follow and `pause` is called between its polls.
pub fn run(args: &[&str], out: &mut dyn Write, err: &mut dyn Write, polls: u64, pause: PauseFn) -> io::Result<ExitCode> {
    let result = parse_args(args).and_then(|(path, follow)| {
        if follow {
            follow_file(&path, polls, out, pause)
        } else {
            follow_file(&path, 1, out, no_pause)
        }
    });
    report(result, err)
}
