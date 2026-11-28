//! The winget run inside a round: room is checked before the run and again with its lines, then everything is appended in one write.

use crate::error::PollError;
use crate::model::PollEnv;
use crate::room::{fits, pending_bytes, refused_bytes};
use crate::round::{DefenderStep, WingetHooks};
use crate::winget::{spool_full_line, winget_lines};
use agent_channel::spool::{append_locked, pause_between_lock_attempts};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;


/// The run id: seconds since the epoch at the run (runs are at least an hour apart); a clock before the epoch gives 0 and a warn.
pub fn run_id_from(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map_or_else(
        |_| {
            warn!("system clock is before the epoch, run id 0");
            0
        },
        |elapsed| elapsed.as_secs(),
    )
}


pub fn current_run_id() -> u64 {
    run_id_from(SystemTime::now())
}


/// The lines that go to the spool: the run, or the `spool_full` summary alone when the run does not fit; `None` when even that does not.
pub fn lines_that_fit(lines: Vec<String>, run_id: u64, pending: u64, limit: u64) -> Option<Vec<String>> {
    let replacement = vec![spool_full_line(run_id)];
    [lines, replacement].into_iter().find(|candidate| fits(pending, candidate, limit))
}


/// Room is checked before winget runs (pending spool below the cap) and again with the lines; one warn per episode.
pub fn spool_winget(env: &mut PollEnv<'_>, hooks: &WingetHooks, blocked: &mut bool) -> Result<DefenderStep, PollError> {
    let limit = env.max_spool_bytes;
    let before = pending_bytes(env.spool).map_err(PollError::SpoolSize)?;
    if before >= limit {
        if !*blocked {
            warn!(pending = before, limit, "spool full, winget not run");
        }
        *blocked = true;
        Ok(DefenderStep::NoRoom)
    } else {
        let run_id = (hooks.run_id)();
        let located = (hooks.locate)();
        let run = winget_lines(&mut *env.run, &located, run_id, env.line_limit);
        let pending = pending_bytes(env.spool).map_err(PollError::SpoolSize)?;
        let refused = refused_bytes(&run.lines);
        let chosen = lines_that_fit(run.lines, run_id, pending, limit);
        if chosen.is_none() && !*blocked {
            warn!(pending, refused, limit, "spool full, winget lines refused");
        }
        *blocked = chosen.is_none();
        match chosen {
            Some(lines) => append_locked(lines.into_iter().map(Ok), env.spool, env.lock_attempts, &mut pause_between_lock_attempts)
                .map(|_| DefenderStep::Appended)
                .map_err(PollError::Spool),
            None => Ok(DefenderStep::Refused),
        }
    }
}
