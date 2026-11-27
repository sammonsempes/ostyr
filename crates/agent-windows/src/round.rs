use crate::cycle::poll_repeat;
use crate::defender_run::defender_once;
use crate::error::PollError;
use crate::model::{ChannelState, PollEnv, PollTotals};
use crate::room::{fits, pending_bytes, refused_bytes};
use crate::settings::{channels_of, observation, Observed, Settings};
use crate::winget_find::{FindError, Located};
use crate::winget_round::spool_winget;
use agent_channel::spool::{append_locked, pause_between_lock_attempts};
use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tracing::warn;


/// What lives between rounds: batch states, defender wait (`None`: never ran), room refusal flag.
#[derive(Debug, Default)]
pub struct RoundState {
    pub channels: BTreeMap<&'static str, ChannelState>,
    pub defender_waited: Option<u64>,
    pub defender_blocked: bool,
    pub winget: Option<WingetHooks>,
    pub winget_waited: Option<u64>,
    pub winget_blocked: bool,
}


/// The winget lookup and the run id source; `None` in `RoundState` disables the winget run.
#[derive(Debug, Clone, Copy)]
pub struct WingetHooks {
    pub locate: fn() -> Result<Located, FindError>,
    pub run_id: fn() -> u64,
}


#[derive(Debug, Default)]
pub struct RoundReport {
    pub polled: Vec<(&'static str, Vec<PollTotals>)>,
    pub defender: bool,
    pub defender_spool_full: u64,
    pub winget: bool,
}


pub fn apply_settings(env: &mut PollEnv<'_>, settings: &Settings) {
    env.max_output_bytes = settings.max_output_bytes;
    env.deadline_seconds = settings.deadline_seconds;
    env.max_spool_bytes = settings.max_spool_bytes;
    env.max_batch = settings.batch;
}


pub fn defender_due(waited: Option<u64>, interval_seconds: u64) -> bool {
    waited.is_none_or(|seconds| seconds >= interval_seconds)
}


pub fn next_waited(waited: Option<u64>, ran: bool, poll_interval_seconds: u64) -> u64 {
    let base = if ran { 0 } else { waited.unwrap_or(0) };
    base.saturating_add(poll_interval_seconds)
}


/// What became of the defender in a round: not run for want of spool room, run but its line refused, or run and appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenderStep {
    NoRoom,
    Refused,
    Appended,
}


/// Room is checked before PowerShell runs (pending spool below the cap) and again with the line; one warn per episode.
pub fn spool_defender_line(env: &mut PollEnv<'_>, blocked: &mut bool) -> Result<DefenderStep, PollError> {
    let limit = env.max_spool_bytes;
    let before = pending_bytes(env.spool).map_err(PollError::SpoolSize)?;
    if before >= limit {
        if !*blocked {
            warn!(pending = before, limit, "spool full, defender not run");
        }
        *blocked = true;
        Ok(DefenderStep::NoRoom)
    } else {
        let line = defender_once(&mut *env.run);
        let pending = pending_bytes(env.spool).map_err(PollError::SpoolSize)?;
        let lines = [line];
        let room = fits(pending, &lines, limit);
        let refused = refused_bytes(&lines);
        if !room && !*blocked {
            warn!(pending, refused, limit, "spool full, defender line refused");
        }
        *blocked = !room;
        let [spooled] = lines;
        if room {
            append_locked(
                std::iter::once(Ok(spooled)),
                env.spool,
                env.lock_attempts,
                &mut pause_between_lock_attempts,
            )
            .map(|_| DefenderStep::Appended)
            .map_err(PollError::Spool)
        } else {
            Ok(DefenderStep::Refused)
        }
    }
}


/// One round over ONE settings snapshot, taken first and used for every channel, the defender run and the wait; the wait is not called on an error.
pub fn run_round(
    engine: &ReloadEngine<Settings>,
    env: &mut PollEnv<'_>,
    round: &mut RoundState,
    wait: &mut dyn FnMut(u64),
) -> Result<RoundReport, PollError> {
    let snapshot = current_config(engine);
    apply_settings(env, &snapshot);
    let polled = channels_of(&snapshot)
        .iter()
        .map(|channel| {
            let state = round.channels.entry(channel.key).or_default();
            poll_repeat(env, channel, state).map(|totals| (channel.key, totals))
        })
        .collect::<Result<Vec<_>, PollError>>()?;
    let defender = defender_due(round.defender_waited, snapshot.defender_interval_seconds);
    let step = if defender {
        Some(spool_defender_line(env, &mut round.defender_blocked)?)
    } else {
        None
    };
    let ran = step.is_some_and(|found| found != DefenderStep::NoRoom);
    round.defender_waited = match step {
        Some(DefenderStep::NoRoom) => round.defender_waited,
        _ => Some(next_waited(round.defender_waited, ran, snapshot.poll_interval_seconds)),
    };
    let winget = run_winget_step(env, round, &snapshot)?;
    wait(snapshot.poll_interval_seconds);
    Ok(RoundReport {
        winget,
        polled,
        defender: ran,
        defender_spool_full: u64::from(step.is_some_and(|found| found != DefenderStep::Appended)),
    })
}


/// The winget run of the round, when it is enabled and due; its wait is kept like the defender's. `true` when it ran.
pub fn run_winget_step(env: &mut PollEnv<'_>, round: &mut RoundState, snapshot: &Settings) -> Result<bool, PollError> {
    match round.winget {
        Some(hooks) if defender_due(round.winget_waited, snapshot.updates_interval_seconds) => {
            let step = spool_winget(env, &hooks, &mut round.winget_blocked)?;
            let ran = step != DefenderStep::NoRoom;
            round.winget_waited = if ran {
                Some(next_waited(round.winget_waited, true, snapshot.poll_interval_seconds))
            } else {
                round.winget_waited
            };
            Ok(ran)
        }
        Some(_) => {
            round.winget_waited = Some(next_waited(round.winget_waited, false, snapshot.poll_interval_seconds));
            Ok(false)
        }
        None => Ok(false),
    }
}


/// Reloads once; a refusal caused by the file itself (never the audit) is remembered with the bytes the loader read.
pub fn reload_once_per_refusal(engine: &ReloadEngine<Settings>, observed: &Mutex<Observed>) {
    let outcome = reload(engine);
    let mut state = observation(observed);
    if matches!(outcome, ReloadOutcome::Refused { .. }) && state.file_fault {
        state.refused = state.bytes.clone();
    }
}


/// Each round first reloads the file (an invalid one is refused, logged and audited by core-config once, the old snapshot stays), then runs.
pub fn run_rounds(
    engine: &ReloadEngine<Settings>,
    observed: &Mutex<Observed>,
    max_rounds: u32,
    env: &mut PollEnv<'_>,
    round: &mut RoundState,
    wait: &mut dyn FnMut(u64),
) -> Result<Vec<RoundReport>, PollError> {
    (0..max_rounds)
        .map(|_| {
            reload_once_per_refusal(engine, observed);
            run_round(engine, env, round, wait)
        })
        .collect()
}
