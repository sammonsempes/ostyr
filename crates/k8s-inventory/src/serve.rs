//! The `ostyr-k8s-inventory` service: one round per interval until the interrupt wait resolves; logs on stderr.

use crate::round::{log_round, one_round};
use crate::service::{load_service_settings, open_service_settings_from, LiveSettings};
use crate::settings::load_settings as load_fetch_settings;
use crate::signals::{reload_on_signals, stop_reloaders, Reloaders};
use crate::types::{InterruptWait, ReloadSignals, StartRead, WaitFn};
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::model::Outcome;
use core_config::reload::{current_config, reload_entry, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::stderr;
use std::path::{absolute, Path};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{error, info, warn};


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


pub const MAX_INTERRUPTS_LOGGED: u64 = 1_000;


/// Says what an interrupt does: the first stops the service after the round in flight, any later one changes nothing.
pub fn announce(name: &'static str, first: Option<oneshot::Sender<()>>) {
    match first {
        Some(sender) => {
            let sent = sender.send(()).is_ok();
            info!(name, sent, "interrupt received, the round in flight finishes first");
        }
        None => warn!(name, "second interrupt ignored, the round in flight finishes first"),
    }
}


/// Hears `limit` interrupts: the first one releases `first`, every later one is logged and ignored.
#[cfg(unix)]
pub async fn announce_interrupts(
    mut terminate: tokio::signal::unix::Signal,
    mut interrupt: tokio::signal::unix::Signal,
    first: oneshot::Sender<()>,
    limit: u64,
) {
    let mut pending = Some(first);
    for _ in 0..limit {
        let name = tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            _ = interrupt.recv() => "SIGINT",
        };
        announce(name, pending.take());
    }
}


/// Completes on the first `SIGTERM` or `SIGINT`; both handlers are installed when this returns, and a task logs every later one by name.
#[cfg(unix)]
pub fn stop_signals() -> std::io::Result<InterruptWait> {
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let (first_sender, first_receiver) = oneshot::channel();
    tokio::spawn(announce_interrupts(terminate, interrupt, first_sender, MAX_INTERRUPTS_LOGGED));
    Ok(Box::pin(async move { first_receiver.await.map_err(std::io::Error::other) }))
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


/// Looks at the interrupt without waiting: a stop asked during the start skips the first round.
pub async fn stop_asked(interrupt: &mut InterruptWait) -> Result<bool, Box<dyn Error>> {
    let asked = tokio::select! {
        biased;
        waited = &mut *interrupt => Some(waited),
        () = std::future::ready(()) => None,
    };
    Ok(asked.transpose()?.is_some())
}


/// The first configuration, audited at start: every setting name and value (paths, tenant, cluster, URL; never a secret), bounded by the audit; entries end in `; ` because a value ending in `token` followed by a newline would make the redactor swallow the next entry.
pub fn audit_start(engine: &ReloadEngine<LiveSettings>) -> Result<(), AuditError> {
    let listing: String = (engine.to_state)(&current_config(engine))
        .iter()
        .map(|(key, value)| format!("{key}={value}; "))
        .collect();
    (engine.audit)(reload_entry(
        &engine.context,
        Outcome::Success,
        [("result", "started".to_owned()), ("diff", listing)],
    ))
    .map(|_record| ())
}


/// Rounds run to their end (the interrupt is looked at between rounds only); then the reload sources are joined and the gate taken.
pub async fn serve(
    engine: &ReloadEngine<LiveSettings>,
    pg: &PgSettings,
    max_rounds: u64,
    wait: WaitFn,
    interrupt: &mut InterruptWait,
    reloaders: Reloaders,
) -> Result<Stop, Box<dyn Error>> {
    let mut rounds = 0;
    let mut stopped = false;
    while !stopped && rounds < MAX_ROUNDS.min(max_rounds) {
        stopped = stop_asked(interrupt).await?;
        if !stopped {
            let live = current_config(engine);
            log_round(&one_round(pg, &live).await);
            rounds += 1;
            let pause_for = Duration::from_secs(live.service.interval_seconds);
            stopped = tokio::select! {
                biased;
                waited = &mut *interrupt => waited.map(|()| true),
                () = wait(pause_for) => Ok(false),
            }?;
        }
    }
    stop_reloaders(reloaders);
    drain_reloads(engine);
    Ok(if stopped { Stop::Interrupted } else { Stop::Capped(rounds) })
}


/// The migrations of the CMDB store, from the start snapshot of the service settings.
pub async fn prepare_store(engine: &ReloadEngine<LiveSettings>) -> Result<PgSettings, Box<dyn Error>> {
    let pg = load_pg_settings(&current_config(engine).service.pg_settings)?;
    migrate(
        &connect(&pg).await?,
        MIGRATION_NAMESPACE,
        &MIGRATIONS,
        Duration::from_secs(pg.statement_timeout_secs),
    )
    .await?;
    Ok(pg)
}


/// `first_read` is the one start read of the service file; the fetch file is read once beside it, and the engine takes both as its baseline.
pub async fn serving_with(
    first_read: StartRead,
    settings_file: &Path,
    max_rounds: u64,
    wait: WaitFn,
    mut interrupt: InterruptWait,
    reload_signals: ReloadSignals,
) -> Result<Stop, Box<dyn Error>> {
    let start_service = first_read(settings_file)?;
    let service_file = absolute(settings_file)?;
    let fetch_file = absolute(&start_service.fetch_settings)?;
    let start_fetch = load_fetch_settings(&fetch_file)?;
    let log = Arc::new(open_file_log(&start_service.audit_file)?);
    let baseline = LiveSettings {
        service: start_service,
        fetch: start_fetch,
    };
    let engine = Arc::new(open_service_settings_from(
        &service_file,
        &fetch_file,
        baseline,
        boxed_reload_audit(&log),
    )?);
    audit_start(&engine)?;
    let watch = watch_files(Arc::clone(&engine), &[service_file, fetch_file], DEBOUNCE)?;
    let reloaders = Reloaders {
        stoppers: vec![reload_on_signals(reload_signals, Arc::clone(&engine)), Box::new(move || watch.stop())],
    };
    match prepare_store(&engine).await {
        Ok(pg) => {
            info!("serving");
            serve(&engine, &pg, max_rounds, wait, &mut interrupt, reloaders).await
        }
        Err(error) => {
            stop_reloaders(reloaders);
            Err(error)
        }
    }
}


/// Answers `Ok` on an interrupt, `RoundCap` when `max_rounds` rounds ran, `Failed` for anything that stopped the start.
pub async fn start(
    settings_file: &Path,
    max_rounds: u64,
    wait: WaitFn,
    interrupt: InterruptWait,
    reload_signals: ReloadSignals,
) -> Result<(), ServeError> {
    let stop = serving_with(load_service_settings, settings_file, max_rounds, wait, interrupt, reload_signals)
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


pub async fn run(arguments: &[String], interrupt: InterruptWait, reload_signals: ReloadSignals) -> Result<(), ServeError> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(ServeError::Usage),
    }?;
    install_logging().map_err(ServeError::Failed)?;
    start(Path::new(settings_file), MAX_ROUNDS, pause, interrupt, reload_signals).await
}
