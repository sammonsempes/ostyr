use crate::error::PackError;
use crate::packs::load_packs;
use crate::schedule::{due_runs, ScheduleError, MAX_DUE_RUNS};
use std::io::{self, Write};
use std::num::ParseIntError;
use std::path::Path;
use thiserror::Error;


pub const USAGE: &str = "usage: hunt_due <packs-dir> <now> [<last-done-end>]";


#[derive(Debug, Error)]
pub enum DueError {
    #[error("{USAGE}")]
    Usage,
    #[error("a time must be unix seconds")]
    Time(#[source] ParseIntError),
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error(transparent)]
    Schedule(#[from] ScheduleError),
    #[error("cannot write the report")]
    Write(#[from] io::Error),
}


/// Writes `id`, start and end, tab separated, one line per due run of every pack (no grace).
pub fn due_files(dir: &str, now: i64, last_done_end: Option<i64>, out: &mut dyn Write) -> Result<(), DueError> {
    load_packs(Path::new(dir))?.iter().try_for_each(|item| {
        due_runs(&item.pack, last_done_end, now, 0, MAX_DUE_RUNS)?
            .iter()
            .try_for_each(|run| writeln!(out, "{}\t{}\t{}", item.pack.id, run.start, run.end).map_err(DueError::from))
    })
}


pub fn run_due(args: &[String], out: &mut dyn Write) -> Result<(), DueError> {
    let parse = |text: &String| text.parse::<i64>().map_err(DueError::Time);
    match args {
        [dir, now] => due_files(dir, parse(now)?, None, out),
        [dir, now, last] => due_files(dir, parse(now)?, Some(parse(last)?), out),
        _ => Err(DueError::Usage),
    }
}
