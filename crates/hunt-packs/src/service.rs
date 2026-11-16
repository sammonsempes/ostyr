use crate::clock::{judge, ClockGuard, Verdict};
use crate::packs::load_packs_partial;
use crate::settings::{tick_limits, HuntSettings};
use crate::store::Param;
use crate::tick::{tick, Hooks};
use crate::types::{ClockFn, SleepFn};
use core_config::error::ConfigError;
use core_config::parse::{read_text_capped, MAX_FILE_BYTES};
use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::future::Future;
use std::path::Path;
use tokio::sync::watch::Receiver;
use tracing::{debug, info, warn};


/// What the loop did, summed over its rounds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ServiceReport {
    pub rounds: u64,
    pub ticks: u64,
    pub runs: usize,
    pub clock_jumps: u64,
    pub reloads_applied: u64,
    pub reloads_refused: u64,
    pub reloads_skipped: u64,
    pub refused_files: usize,
    pub refused_tenants: usize,
    pub pack_dir_failures: u64,
    pub tick_failures: u64,
}


/// Ceiling on the caller's round cap (centuries at the shortest tick).
pub const MAX_ROUNDS: u64 = 1_000_000_000;


/// The settings engine and the file it loads, polled once per round.
pub struct SettingsSource<'source> {
    pub engine: &'source ReloadEngine<HuntSettings>,
    pub path: &'source Path,
}


pub struct ServiceState {
    pub guard: ClockGuard,
    pub report: ServiceReport,
    pub closed: bool,
    pub refused_digest: Option<String>,
}


/// SHA-256 of the settings file, read through core-config's capped reader.
pub fn settings_digest(path: &Path) -> Result<String, ConfigError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    let text = read_text_capped(&mut handle, &file, MAX_FILE_BYTES)?;
    Ok(format!("{:x}", Sha256::digest(text.as_bytes())))
}


/// The digest, or `None` (logged) when the file cannot be read: then the reload runs and refuses it by itself.
pub fn digest_or_none(path: &Path) -> Option<String> {
    settings_digest(path)
        .inspect_err(|error| {
            let text = error.to_string();
            debug!("hunt settings digest unavailable: {text}");
        })
        .ok()
}


/// One reload per round, skipped while the file holds the already refused bytes (remembered only if unchanged during the reload).
pub fn reload_round(engine: &ReloadEngine<HuntSettings>, settings_path: &Path, refused_digest: &mut Option<String>, report: &mut ServiceReport) {
    let before = digest_or_none(settings_path);
    if before.is_some() && before == *refused_digest {
        report.reloads_skipped += 1;
    } else {
        let outcome = reload(engine);
        let after = digest_or_none(settings_path);
        let refused = matches!(outcome, ReloadOutcome::Refused { .. });
        match outcome {
            ReloadOutcome::Applied { .. } => report.reloads_applied += 1,
            ReloadOutcome::Refused { .. } => report.reloads_refused += 1,
            ReloadOutcome::Unchanged => (),
        }
        *refused_digest = if refused && before == after { before } else { None };
    }
}


/// The packs are re-read from the directory, then one tick runs with `now`.
pub async fn tick_round<Executor, Pending>(settings: &HuntSettings, now: i64, exec: &mut Executor, hooks: &mut Hooks<'_>, report: &mut ServiceReport)
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    match load_packs_partial(&settings.packs_dir) {
        Err(error) => {
            let text = error.to_string();
            warn!("hunt packs directory unreadable: {text}");
            report.pack_dir_failures += 1;
        }
        Ok(set) => {
            report.refused_files += set.refused;
            let packs: Vec<_> = set.packs.into_iter().map(|item| item.pack).collect();
            match tick(&settings.tenants, &packs, now, &tick_limits(settings), exec, hooks).await {
                Ok(done) => {
                    report.ticks += 1;
                    report.runs += done.packs.iter().map(|entry| entry.runs.len()).sum::<usize>();
                    report.refused_tenants += done.refused_tenants;
                }
                Err(error) => {
                    let text = error.to_string();
                    warn!("hunt tick refused: {text}");
                    report.tick_failures += 1;
                }
            }
        }
    }
}


/// One round: reload, read both clocks, run the tick unless the wall clock jumped; gives the seconds to sleep.
pub async fn round<Executor, Pending>(
    source: &SettingsSource<'_>,
    clock: &mut ClockFn<'_>,
    exec: &mut Executor,
    hooks: &mut Hooks<'_>,
    state: &mut ServiceState,
) -> u64
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    reload_round(source.engine, source.path, &mut state.refused_digest, &mut state.report);
    let settings = current_config(source.engine);
    state.report.rounds += 1;
    let reading = clock();
    match judge(&mut state.guard, reading) {
        Verdict::Run => tick_round(&settings, reading.wall, exec, hooks, &mut state.report).await,
        Verdict::Jump { wall_delta, mono_delta } => {
            let (wall, mono) = (wall_delta, mono_delta);
            warn!("hunt clock jump: wall clock moved {wall} s, monotonic clock {mono} s: no pack run this round");
            state.report.clock_jumps += 1;
        }
    }
    settings.tick_seconds
}


/// Sleeps `seconds`, woken early by `stop`; a dropped sender counts as a stop.
pub async fn pause(sleep: &mut SleepFn<'_>, stop: &mut Receiver<bool>, seconds: u64) -> bool {
    tokio::select! {
        () = sleep(seconds) => false,
        changed = stop.changed() => changed.is_err(),
    }
}


/// The loop: `while !stopped && rounds < max_ticks`, each round one reload, one clock check, at most one tick, then a sleep.
pub async fn run_service<Executor, Pending>(
    source: &SettingsSource<'_>,
    clock: &mut ClockFn<'_>,
    sleep: &mut SleepFn<'_>,
    stop: &mut Receiver<bool>,
    max_ticks: u64,
    exec: &mut Executor,
    hooks: &mut Hooks<'_>,
) -> ServiceReport
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let mut state = ServiceState {
        guard: ClockGuard::default(),
        report: ServiceReport::default(),
        closed: false,
        refused_digest: None,
    };
    while !state.closed && !*stop.borrow() && state.report.rounds < max_ticks.min(MAX_ROUNDS) {
        let seconds = round(source, clock, exec, hooks, &mut state).await;
        state.closed = pause(sleep, stop, seconds).await;
    }
    let ServiceState { report, .. } = state;
    let (rounds, ticks) = (report.rounds, report.ticks);
    info!("hunt service stopped after {rounds} rounds, {ticks} ticks");
    report
}
