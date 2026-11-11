use crate::error::RpzError;
use crate::model::{Reloader, RunSummary};
use crate::policy::Policy;
use crate::run::generate;
use crate::types::{ClockFn, OpenFn};
use crate::unbound::reload_zone;
use core_config::reload::{current_config, reload, ReloadEngine};
use core_config::reload_cli::{write_outcome, QUIT_COMMAND};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::error;


/// Command results go to `report`.
pub struct Session<'a> {
    pub engine: &'a ReloadEngine<Policy>,
    pub clock: &'a ClockFn<'a>,
    pub open: &'a OpenFn<'a>,
    pub rejected: &'a AtomicU64,
    pub counter: &'a Path,
    pub output: &'a Path,
    pub reloader: &'a Reloader<'a>,
    pub report: &'a mut dyn Write,
}


/// A failed run is reported and logged, it does not end the session.
pub fn run_generation(session: &mut Session) -> io::Result<()> {
    let policy = current_config(session.engine);
    let instant = (session.clock)();
    let result: Result<_, RpzError> = (session.open)(instant)
        .map_err(RpzError::from)
        .and_then(|mut input| generate(&policy, &mut input, instant, session.counter, session.output))
        .map(|summary| RunSummary {
            source_bad_rows: session.rejected.load(Ordering::Relaxed),
            ..summary
        });
    match result {
        Ok(summary) => {
            serde_json::to_writer(&mut *session.report, &summary)?;
            writeln!(session.report)?;
            match reload_zone(&policy, session.reloader) {
                Ok(()) => Ok(()),
                Err(failure) => writeln!(session.report, "failed reload {failure}"),
            }
        }
        Err(failure) => {
            error!(%failure, "zone generation failed");
            writeln!(session.report, "failed {failure}")
        }
    }
}


/// `run` generates the zone from the current policy, `reload` reloads the policy file.
pub fn run_command(session: &mut Session, command: &str) -> io::Result<()> {
    match command.trim() {
        "run" => run_generation(session),
        "reload" => write_outcome(&reload(session.engine), &mut session.report),
        other => writeln!(session.report, "unknown command `{other}`"),
    }
}


/// Reads commands until `quit` or end of input.
pub fn run_session(session: &mut Session, input: &mut dyn BufRead) -> io::Result<()> {
    input
        .lines()
        .take_while(|line| line.as_ref().map_or(true, |text| text.trim() != QUIT_COMMAND))
        .try_for_each(|line| line.and_then(|command| run_command(session, &command)))
}
