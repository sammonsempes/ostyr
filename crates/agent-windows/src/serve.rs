//! The `ostyr-agent-windows` service: rounds over the settings file until the interrupt wait resolves; logs on stderr.

use crate::model::{PollEnv, RunRequest, LOCK_ATTEMPTS, MAX_EVENTS_PER_POLL, MAX_OUTPUT_BYTES, QUERY_DEADLINE_SECONDS, WEVTUTIL_PATH};
use crate::round::{reload_once_per_refusal, run_round, RoundState};
use crate::settings::{audit_file_of, observed_load, open_settings_from, settings_path, validate_settings, OpenError, SettingsError};
use crate::settings::{Settings, DEFAULT_MAX_SPOOL_BYTES};
use crate::types::{InterruptWait, Pace, RunFn, SharedObserved};
use agent_channel::error::AppError;
use agent_channel::model::DEFAULT_MAX_MESSAGE_BYTES;
use agent_channel::spool_dirs::open_parent;
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::error::ConfigError;
use core_config::reload::{current_config, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_export::ecs::to_json;
use ecs_normalise::types::SeenIds;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{info, warn};


pub const USAGE: &str = "usage: ostyr-agent-windows <state-dir> <spool>";


pub const MAX_ROUNDS: u64 = 100_000_000;


pub const EXIT_ROUND_CAP: u8 = 3;


pub const GUARD_COUNT: usize = 2;


pub const LINE_LIMIT_DIVISOR: usize = 2;


pub const ACTOR: &str = "agent-windows";


pub const AUDIT_TENANT: &str = "all";


pub const AUDIT_TARGET: &str = "settings.yaml";


pub const AUDIT_REQUEST: &str = "reload";


#[derive(Debug, Error)]
pub enum StartError {
    #[error("state directory refused")]
    StateDir(#[source] AppError),
    #[error("spool directory refused")]
    SpoolDir(#[source] AppError),
    #[error("settings file refused")]
    Read(#[source] ConfigError),
    #[error("settings refused")]
    Invalid(#[from] SettingsError),
    #[error("settings not opened")]
    Open(#[from] OpenError),
    #[error("audit file refused")]
    Audit(#[from] AuditError),
}


#[derive(Debug, Error)]
pub enum ServeError {
    #[error("{USAGE}")]
    Usage,
    #[error("stopped at the round cap of {MAX_ROUNDS} rounds, restart the service")]
    RoundCap,
    #[error("cannot start")]
    Start(#[from] StartError),
    #[error("cannot install logging")]
    Logging(#[source] Box<dyn Error + Send + Sync>),
    #[error("cannot wait for the stop signal")]
    Interrupt(#[source] std::io::Error),
    #[error("the round worker failed")]
    Worker(#[source] JoinError),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Interrupted,
    RoundCap,
}


/// Everything the start produced, kept for the life of the rounds (the directory handles stay open).
pub struct Started {
    pub engine: ReloadEngine<Settings>,
    pub observed: SharedObserved,
    pub guards: [File; GUARD_COUNT],
}


pub fn exit_code(result: &Result<(), ServeError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(ServeError::RoundCap) => ExitCode::from(EXIT_ROUND_CAP),
        Err(_) => ExitCode::FAILURE,
    }
}


/// The error and its causes on one line.
pub fn error_line(error: &dyn Error) -> String {
    std::iter::successors(Some(error), |inner: &&dyn Error| (*inner).source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}


pub fn install_logging() -> Result<(), ServeError> {
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::stderr).with_ansi(false).finish())
        .map_err(|error| ServeError::Logging(Box::new(error)))
}


pub fn reload_context() -> ReloadContext {
    ReloadContext {
        actor_id: ACTOR.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: ACTOR.to_owned(),
        target: AUDIT_TARGET.to_owned(),
        request_id: AUDIT_REQUEST.to_owned(),
    }
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


/// Judges both directories, reads the settings file once, opens the audit file it names and the engine on that same read.
pub fn start_site(state_dir: &Path, spool: &Path) -> Result<Started, StartError> {
    let file = settings_path(state_dir);
    let (state_handle, _) = open_parent(&file).map_err(StartError::StateDir)?;
    let (spool_handle, _) = open_parent(spool).map_err(StartError::SpoolDir)?;
    let observed = SharedObserved::default();
    let first = observed_load(&file, &observed).map_err(StartError::Read)?;
    validate_settings(&first)?;
    let log = Arc::new(open_file_log(&state_dir.join(audit_file_of(&first)?))?);
    let engine = open_settings_from(file, first, boxed_reload_audit(&log), reload_context(), Arc::clone(&observed))?;
    Ok(Started {
        engine,
        observed,
        guards: [state_handle, spool_handle],
    })
}


/// A stop (a message or the sender dropped) ends the wait at once.
pub fn wait_or_stop(stop: &Receiver<()>, pace: Pace, seconds: u64) -> bool {
    !matches!(stop.recv_timeout(pace(seconds)), Err(RecvTimeoutError::Timeout))
}


/// One round: reload, run, log. A failed round backs off for one poll interval itself (`run_round` returns an error without waiting).
pub fn one_round(started: &Started, env: &mut PollEnv<'_>, round: &mut RoundState, stop: &Receiver<()>, pace: Pace, stopped: &mut bool) {
    reload_once_per_refusal(&started.engine, &started.observed);
    let mut wait = |seconds: u64| *stopped = wait_or_stop(stop, pace, seconds);
    match run_round(&started.engine, env, round, &mut wait) {
        Ok(report) => {
            let polled = report.polled.len();
            let defender = report.defender;
            let defender_spool_full = report.defender_spool_full;
            info!(polled, defender, defender_spool_full, "round done");
        }
        Err(error) => {
            let category = error.to_string();
            warn!(category, "round failed, retrying after the pause");
            let seconds = current_config(&started.engine).poll_interval_seconds;
            *stopped = wait_or_stop(stop, pace, seconds);
        }
    }
}


/// Rounds until a stop arrives or `max_rounds` rounds ran.
pub fn serve_rounds(started: &Started, state_dir: &Path, spool: &Path, max_rounds: u64, run_fn: RunFn, pace: Pace, stop: &Receiver<()>) -> Stop {
    let mut seen = SeenIds::new();
    let mut run = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| run_fn(request, sink);
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir,
        spool,
        line_limit: DEFAULT_MAX_MESSAGE_BYTES / LINE_LIMIT_DIVISOR,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: MAX_OUTPUT_BYTES,
        deadline_seconds: QUERY_DEADLINE_SECONDS,
        max_spool_bytes: DEFAULT_MAX_SPOOL_BYTES,
        max_batch: MAX_EVENTS_PER_POLL,
        seen: &mut seen,
    };
    let mut round = RoundState::default();
    let mut stopped = false;
    (0..max_rounds)
        .find_map(|_| {
            one_round(started, &mut env, &mut round, stop, pace, &mut stopped);
            stopped.then_some(Stop::Interrupted)
        })
        .unwrap_or(Stop::RoundCap)
}


pub fn seconds(count: u64) -> Duration {
    Duration::from_secs(count)
}


/// Completes on `SIGTERM` or `SIGINT`; both handlers are installed when this returns.
#[cfg(unix)]
pub fn stop_signals() -> std::io::Result<InterruptWait> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = terminate.recv() => (),
            _ = interrupt.recv() => (),
        }
        Ok(())
    }))
}


/// Completes on Ctrl-C, Ctrl-Break, console close or shutdown; the handlers are installed when this returns.
#[cfg(not(unix))]
pub fn stop_signals() -> std::io::Result<InterruptWait> {
    let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
    let mut ctrl_break = tokio::signal::windows::ctrl_break()?;
    let mut close = tokio::signal::windows::ctrl_close()?;
    let mut shutdown = tokio::signal::windows::ctrl_shutdown()?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = ctrl_c.recv() => (),
            _ = ctrl_break.recv() => (),
            _ = close.recv() => (),
            _ = shutdown.recv() => (),
        }
        Ok(())
    }))
}


/// Starts, then runs the rounds on a blocking thread until `interrupt` resolves (the stop is the sender dropped) or the cap is reached.
pub async fn start(state_dir: &Path, spool: &Path, max_rounds: u64, run_fn: RunFn, pace: Pace, interrupt: InterruptWait) -> Result<(), ServeError> {
    let started = start_site(state_dir, spool)?;
    let (stop_sender, stop_receiver) = std::sync::mpsc::channel::<()>();
    let (state_owned, spool_owned) = (state_dir.to_path_buf(), spool.to_path_buf());
    let mut worker =
        tokio::task::spawn_blocking(move || serve_rounds(&started, &state_owned, &spool_owned, max_rounds, run_fn, pace, &stop_receiver));
    let ended = tokio::select! {
        biased;
        waited = interrupt => {
            waited.map_err(ServeError::Interrupt)?;
            drop(stop_sender);
            worker.await
        },
        done = &mut worker => done,
    };
    match ended.map_err(ServeError::Worker)? {
        Stop::Interrupted => Ok(()),
        Stop::RoundCap => Err(ServeError::RoundCap),
    }
}


pub async fn run(arguments: &[String], interrupt: InterruptWait) -> Result<(), ServeError> {
    let (state_dir, spool) = match arguments {
        [state_dir, spool] => Ok((state_dir, spool)),
        _ => Err(ServeError::Usage),
    }?;
    install_logging()?;
    start(
        Path::new(state_dir),
        Path::new(spool),
        MAX_ROUNDS,
        crate::run::run_process,
        seconds,
        interrupt,
    )
    .await
}
