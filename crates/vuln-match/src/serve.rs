//! The `ostyr-vuln` service: scheduled rounds until the interrupt wait resolves; logs on stderr.

use crate::service::{
    load_settings, log_round, open_service_settings_from, refresh, scan_round, stopped, Loaded, RoundReport, ServiceSettings, MAX_ROUNDS,
};
use crate::store::{MIGRATIONS, MIGRATION_DEADLINE, MIGRATION_NAMESPACE};
use crate::types::{InterruptWait, NowFn, StartRead, WaitFn};
use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::stderr;
use std::path::Path;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::watch::{channel, Receiver};
use tracing::{error, info, warn};


pub const USAGE: &str = "usage: ostyr-vuln <service.yaml>";


pub const EXIT_ROUND_CAP: u8 = 3;


pub const DEBOUNCE: Duration = Duration::from_millis(300);


pub const SCAN_DEADLINE: Duration = Duration::from_secs(120);


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
    Capped,
}


/// Test seams of the start and the stop: the audit wrapper, the point where the reload paths are live, the point before the drain.
pub struct Hooks<'a> {
    pub wrap_audit: &'a dyn Fn(Box<SharedAuditFn>) -> Box<SharedAuditFn>,
    pub ready: &'a dyn Fn(),
    pub before_drain: &'a dyn Fn(),
}


pub fn same_audit(audit: Box<SharedAuditFn>) -> Box<SharedAuditFn> {
    audit
}


pub fn nothing() {}


pub fn plain_hooks() -> Hooks<'static> {
    Hooks {
        wrap_audit: &same_audit,
        ready: &nothing,
        before_drain: &nothing,
    }
}


pub fn pause(duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(tokio::time::sleep(duration))
}


/// A clock before the epoch reads 0, which a round refuses to run on; a time beyond `u64` microseconds saturates and is refused by the store.
pub fn micros_since_epoch(reading: Result<Duration, SystemTimeError>) -> u64 {
    match reading {
        Ok(elapsed) => u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        Err(error) => {
            warn!(%error, "the clock is before the epoch");
            0
        }
    }
}


pub fn system_now_micros() -> u64 {
    micros_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH))
}


pub fn exit_code(result: &Result<(), ServeError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(ServeError::RoundCap) => ExitCode::from(EXIT_ROUND_CAP),
        Err(_) => ExitCode::FAILURE,
    }
}


/// The thread that answers `SIGHUP`; dropping it closes the stream and joins the thread, so a handler in flight has returned when the drop does.
#[cfg(unix)]
pub struct SignalWorker {
    pub handle: signal_hook::iterator::Handle,
    pub thread: Option<std::thread::JoinHandle<()>>,
}


#[cfg(unix)]
impl Drop for SignalWorker {
    fn drop(&mut self) {
        self.handle.close();
        let panicked = self
            .thread
            .take()
            .map(std::thread::JoinHandle::join)
            .is_some_and(|joined| joined.is_err());
        if panicked {
            error!("the signal thread panicked");
        }
    }
}


#[cfg(unix)]
pub fn spawn_signal_worker(signals: &[std::os::raw::c_int], on_signal: crate::types::SignalHandler) -> std::io::Result<SignalWorker> {
    let mut stream = signal_hook::iterator::Signals::new(signals)?;
    let handle = stream.handle();
    let thread = std::thread::spawn(move || stream.forever().for_each(on_signal));
    Ok(SignalWorker {
        handle,
        thread: Some(thread),
    })
}


#[cfg(unix)]
pub fn keep_signals<Config: Send + Sync + 'static>(engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<SignalWorker> {
    let owned = Arc::clone(engine);
    spawn_signal_worker(
        &[signal_hook::consts::SIGHUP],
        Box::new(move |signal| {
            let outcome = core_config::reload::reload(&owned);
            tracing::debug!(signal, ?outcome, "reload after signal");
        }),
    )
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
impl Drop for NoSignals {
    fn drop(&mut self) {}
}


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
    }))
}


#[cfg(not(unix))]
pub fn stop_signals() -> std::io::Result<InterruptWait> {
    Ok(Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(%error, "cannot listen for the interrupt signal");
        }
    }))
}


pub fn install_logging() -> Result<(), Box<dyn Error>> {
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).with_ansi(false).finish())?;
    Ok(())
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


/// One round: a store that cannot be reached runs nothing and is retried after the pause.
pub async fn one_round(
    pg: &PgSettings,
    scope: &TenantScope,
    settings: &ServiceSettings,
    loaded: &Loaded,
    now_micros: u64,
    stop: &Receiver<bool>,
) -> RoundReport {
    match connect(pg).await {
        Ok(client) => {
            let exec = pg_executor(&client, SCAN_DEADLINE);
            let rebuild_exec = pg_executor(&client, MIGRATION_DEADLINE);
            scan_round(&exec, &rebuild_exec, scope, settings, loaded, now_micros, stop).await
        }
        Err(error) => {
            warn!(%error, "the findings store is unreachable, retrying after the pause");
            RoundReport {
                skipped: true,
                ..RoundReport::default()
            }
        }
    }
}


/// Rounds until the stop flag is set or `max_rounds` ran; a round in flight is never cancelled, it checks the flag between assets.
pub async fn serve_rounds(
    engine: &ReloadEngine<ServiceSettings>,
    pg: &PgSettings,
    scope: &TenantScope,
    max_rounds: u64,
    now: &NowFn<'_>,
    wait: &WaitFn<'_>,
    stop: &mut Receiver<bool>,
) -> Stop {
    let mut loaded = Loaded::default();
    let watcher = stop.clone();
    for _round in (0..max_rounds.min(MAX_ROUNDS)).take_while(|_| !stopped(&watcher)) {
        let settings = current_config(engine);
        let (fresh, degraded) = refresh(loaded, &settings);
        loaded = fresh;
        let report = one_round(pg, scope, &settings, &loaded, now(), stop).await;
        log_round(&report, degraded);
        tokio::select! {
            _ = wait(Duration::from_secs(settings.round_seconds)) => (),
            _ = stop.changed() => (),
        }
    }
    if stopped(stop) {
        Stop::Interrupted
    } else {
        Stop::Capped
    }
}


/// True when the interrupt had already resolved; a pending one is left untouched and can be awaited later.
pub async fn interrupted_now(interrupt: &mut InterruptWait) -> bool {
    tokio::select! {
        biased;
        _ = interrupt => true,
        _ = std::future::ready(()) => false,
    }
}


/// Takes the gate every reload holds from its audit to its swap, so a reload in flight finishes before the caller returns.
pub fn drain<Config>(engine: &ReloadEngine<Config>) -> std::sync::LockResult<std::sync::MutexGuard<'_, ()>> {
    engine.gate.lock()
}


pub async fn migrate_stores(pg: &PgSettings) -> Result<(), Box<dyn Error>> {
    let client = connect(pg).await?;
    let deadline = Duration::from_secs(pg.statement_timeout_secs);
    let applied = migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, deadline).await?.len();
    let alert_applied = migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, deadline).await?.len();
    info!(applied, alert_applied, "migrations checked");
    Ok(())
}


/// `first_read` is the one start read; the audit path and the baseline of the start-only settings both come from it.
pub async fn serving_with(
    first_read: StartRead,
    settings_file: &Path,
    max_rounds: u64,
    now: &NowFn<'_>,
    wait: &WaitFn<'_>,
    interrupt: InterruptWait,
    hooks: &Hooks<'_>,
) -> Result<Stop, Box<dyn Error>> {
    let start_settings = first_read(settings_file)?;
    let log = Arc::new(open_file_log(&start_settings.audit_file)?);
    let audit = (hooks.wrap_audit)(boxed_reload_audit(&log));
    let engine = Arc::new(open_service_settings_from(settings_file, start_settings, audit)?);
    let first = current_config(&engine);
    let scope = tenant_scope(&first.tenant)?;
    let pg = load_pg_settings(&first.pg_settings)?;
    let signals = keep_signals(&engine)?;
    migrate_stores(&pg).await?;
    let watch = watch_files(Arc::clone(&engine), &[settings_file.to_path_buf()], DEBOUNCE)?;
    let (stop_sender, mut stop) = channel(false);
    let mut pending_interrupt = interrupt;
    if interrupted_now(&mut pending_interrupt).await {
        warn!("a stop arrived before the first round, no round runs");
        stop_sender.send_replace(true);
    } else {
        tokio::spawn(async move {
            pending_interrupt.await;
            stop_sender.send_replace(true);
        });
    }
    (hooks.ready)();
    info!(tenant = first.tenant, "serving");
    let ended = serve_rounds(&engine, &pg, &scope, max_rounds, now, wait, &mut stop).await;
    (hooks.before_drain)();
    watch.stop();
    drop(signals);
    let _gate = drain(&engine);
    Ok(ended)
}


/// Answers `Ok` on an interrupt, `RoundCap` when `max_rounds` rounds ran, `Failed` for anything that stopped the start.
pub async fn start(settings_file: &Path, max_rounds: u64, now: &NowFn<'_>, wait: &WaitFn<'_>, interrupt: InterruptWait) -> Result<(), ServeError> {
    let ended = serving_with(load_settings, settings_file, max_rounds, now, wait, interrupt, &plain_hooks())
        .await
        .map_err(ServeError::Failed)?;
    match ended {
        Stop::Interrupted => Ok(()),
        Stop::Capped => {
            error!(max_rounds, "round_cap_reached, exiting");
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
    start(Path::new(settings_file), MAX_ROUNDS, &system_now_micros, &pause, interrupt).await
}
