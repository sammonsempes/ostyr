//! The `ostyr-k8s-inventory` service: one round per interval until the interrupt wait resolves; logs on stderr.

use crate::round::{log_round, one_round};
use crate::service::{load_service_settings, open_service_settings_from, ServiceSettings};
use crate::types::{InterruptWait, StartRead, WaitFn};
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::stderr;
use std::path::Path;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use thiserror::Error;
use tracing::{error, info};


pub const USAGE: &str = "usage: ostyr-k8s-inventory <service.yaml>";


pub const MAX_ROUNDS: u64 = 10_000_000;


pub const EXIT_ROUND_CAP: u8 = 3;


pub const DEBOUNCE: Duration = Duration::from_millis(300);


#[derive(Debug, Error)]
pub enum ServeError {
    #[error("{USAGE}")]
    Usage,
    #[error("stopped at the round cap of {MAX_ROUNDS} rounds, restart the service")]
    RoundCap,
    #[error("{0}")]
    Failed(#[source] Box<dyn Error>),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Interrupted,
    Capped(u64),
}


pub fn pause(duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


pub fn exit_code(result: &Result<(), ServeError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(ServeError::RoundCap) => ExitCode::from(EXIT_ROUND_CAP),
        Err(_) => ExitCode::FAILURE,
    }
}


#[cfg(unix)]
pub fn keep_signals<Config: Send + Sync + 'static>(engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(Arc::clone(engine), &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
pub fn keep_signals<Config>(_engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<NoSignals> {
    Ok(NoSignals)
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


#[cfg(not(unix))]
pub fn stop_signals() -> std::io::Result<InterruptWait> {
    Ok(Box::pin(tokio::signal::ctrl_c()))
}


pub fn install_logging() -> Result<(), Box<dyn Error>> {
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).with_ansi(false).finish())?;
    Ok(())
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


/// Takes the reload gate, so a reload in flight has stored, published and audited its record before this returns.
pub fn drain_reloads<Config>(engine: &ReloadEngine<Config>) {
    let _drained = engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
}


/// A round runs to its end: the interrupt is only looked at while waiting, so a stop never cuts a fetch or a sync.
pub async fn serve(
    engine: &ReloadEngine<ServiceSettings>,
    pg: &PgSettings,
    max_rounds: u64,
    wait: WaitFn,
    interrupt: &mut InterruptWait,
) -> Result<Stop, Box<dyn Error>> {
    let mut rounds = 0;
    let mut stopped = false;
    while !stopped && rounds < MAX_ROUNDS.min(max_rounds) {
        let live = current_config(engine);
        log_round(&one_round(pg, &live).await);
        rounds += 1;
        let pause_for = Duration::from_secs(live.interval_seconds);
        stopped = tokio::select! {
            biased;
            waited = &mut *interrupt => waited.map(|()| true),
            () = wait(pause_for) => Ok(false),
        }?;
    }
    drain_reloads(engine);
    Ok(if stopped { Stop::Interrupted } else { Stop::Capped(rounds) })
}


/// `first_read` is the one start read; a test swaps the file inside it to show where the audit path and the baseline come from.
pub async fn serving_with(
    first_read: StartRead,
    settings_file: &Path,
    max_rounds: u64,
    wait: WaitFn,
    mut interrupt: InterruptWait,
) -> Result<Stop, Box<dyn Error>> {
    let start_settings = first_read(settings_file)?;
    let log = Arc::new(open_file_log(&start_settings.audit_file)?);
    let engine = Arc::new(open_service_settings_from(settings_file, start_settings, boxed_reload_audit(&log))?);
    let _watch = watch_files(Arc::clone(&engine), &[settings_file.to_path_buf()], DEBOUNCE)?;
    let _signals = keep_signals(&engine)?;
    let pg = load_pg_settings(&current_config(&engine).pg_settings)?;
    migrate(
        &connect(&pg).await?,
        MIGRATION_NAMESPACE,
        &MIGRATIONS,
        Duration::from_secs(pg.statement_timeout_secs),
    )
    .await?;
    info!("serving");
    serve(&engine, &pg, max_rounds, wait, &mut interrupt).await
}


/// Answers `Ok` on an interrupt, `RoundCap` when `max_rounds` rounds ran, `Failed` for anything that stopped the start.
pub async fn start(settings_file: &Path, max_rounds: u64, wait: WaitFn, interrupt: InterruptWait) -> Result<(), ServeError> {
    let stop = serving_with(load_service_settings, settings_file, max_rounds, wait, interrupt)
        .await
        .map_err(ServeError::Failed)?;
    match stop {
        Stop::Interrupted => Ok(()),
        Stop::Capped(rounds) => {
            error!(rounds, "round_cap_reached, exiting");
            Err(ServeError::RoundCap)
        }
    }
}


pub async fn run(arguments: &[String], interrupt: InterruptWait) -> Result<(), ServeError> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(ServeError::Usage),
    }?;
    install_logging().map_err(ServeError::Failed)?;
    start(Path::new(settings_file), MAX_ROUNDS, pause, interrupt).await
}
