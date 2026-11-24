//! The `ostyr-metric-alerts` service: rounds over every listed tenant until the interrupt wait resolves; logs on stderr.

use crate::fetch::{agent_for, fetch_points, load_fetch_settings, read_key, FetchError};
use crate::service::{load_settings, open_rules, open_service_settings, run_pass, serve, Live, PassReport, ServeEnd, MAX_ROUNDS};
use crate::types::{InterruptWait, NowFn, PassFuture, TenantStates, Timestamp, WaitFn};
use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::migrate::migrate;
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
use tokio::sync::Mutex;
use tracing::{error, info, warn};


pub const USAGE: &str = "usage: ostyr-metric-alerts <service.yaml>";


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


#[derive(Debug, Error)]
pub enum PassFault {
    #[error("the metric store could not be read")]
    Fetch(#[from] FetchError),
    #[error("the alerts store is unreachable")]
    Pg(#[from] PgError),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Interrupted,
    Capped(ServeEnd),
}


pub fn pause(duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


/// A clock before the epoch reads 0, which `next_now` never runs.
pub fn seconds_since_epoch(reading: Result<Duration, SystemTimeError>) -> Timestamp {
    match reading {
        Ok(elapsed) => elapsed.as_secs(),
        Err(error) => {
            warn!(%error, "the clock is before the epoch");
            0
        }
    }
}


pub fn system_now() -> Timestamp {
    seconds_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH))
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


pub fn pass_fault_class(fault: &PassFault) -> &'static str {
    match fault {
        PassFault::Fetch(_) => "metric_store",
        PassFault::Pg(_) => "alerts_store",
    }
}


/// Settings are read again every pass, so a swapped `fetch_settings` file applies to the next round.
pub async fn connected_pass(pg: &PgSettings, states: &Mutex<TenantStates>, live: &Live, now: Timestamp) -> Result<PassReport, PassFault> {
    let fetch_settings = load_fetch_settings(&live.settings.fetch_settings)?;
    let agent = agent_for(&fetch_settings)?;
    let password = read_key(&fetch_settings)?;
    let client = connect(pg).await?;
    let exec = pg_executor(&client, Duration::from_secs(pg.statement_timeout_secs));
    let timeout = Duration::from_millis(fetch_settings.timeout_ms);
    let fetch = |query: &_| fetch_points(&agent, &fetch_settings, &password, query, timeout);
    let mut tenant_states = states.lock().await;
    Ok(run_pass(&exec, &fetch, live, now, &mut tenant_states).await)
}


/// A pass that cannot reach a store runs nothing and is retried after the next pause.
pub async fn one_pass(pg: Arc<PgSettings>, states: Arc<Mutex<TenantStates>>, live: Live, now: Timestamp) -> PassReport {
    match connected_pass(&pg, &states, &live, now).await {
        Ok(report) => report,
        Err(fault) => {
            let class = pass_fault_class(&fault);
            warn!(class, "round not run, retrying after the pause");
            PassReport {
                unavailable: 1,
                ..PassReport::default()
            }
        }
    }
}


pub async fn serving(
    settings_file: &Path,
    max_rounds: u64,
    now: &NowFn<'_>,
    wait: &WaitFn<'_>,
    interrupt: InterruptWait,
) -> Result<Stop, Box<dyn Error>> {
    let log = Arc::new(open_file_log(&load_settings(settings_file)?.audit_file)?);
    let settings_engine = Arc::new(open_service_settings(settings_file, boxed_reload_audit(&log))?);
    let first = current_config(&settings_engine);
    let rules_engine = Arc::new(open_rules(&first.rules_file, boxed_reload_audit(&log))?);
    let _settings_watch = watch_files(Arc::clone(&settings_engine), &[settings_file.to_path_buf()], DEBOUNCE)?;
    let _rules_watch = watch_files(Arc::clone(&rules_engine), std::slice::from_ref(&first.rules_file), DEBOUNCE)?;
    let _settings_signals = keep_signals(&settings_engine)?;
    let _rules_signals = keep_signals(&rules_engine)?;
    let pg = Arc::new(load_pg_settings(&first.pg_settings)?);
    migrate(
        &connect(&pg).await?,
        MIGRATION_NAMESPACE,
        &MIGRATIONS,
        Duration::from_secs(pg.statement_timeout_secs),
    )
    .await?;
    let states = Arc::new(Mutex::new(TenantStates::new()));
    let live = || Live {
        settings: current_config(&settings_engine),
        rules: current_config(&rules_engine),
    };
    let mut pass = |snapshot: Live, at: Timestamp| -> PassFuture { Box::pin(one_pass(Arc::clone(&pg), Arc::clone(&states), snapshot, at)) };
    let tenants = first.tenants.len();
    info!(tenants, "serving");
    tokio::select! {
        biased;
        waited = interrupt => {
            waited?;
            Ok(Stop::Interrupted)
        },
        end = serve(max_rounds, &live, now, &mut pass, wait) => Ok(Stop::Capped(end)),
    }
}


/// Answers `Ok` on an interrupt, `RoundCap` when `max_rounds` rounds ran, `Failed` for anything that stopped the start.
pub async fn start(settings_file: &Path, max_rounds: u64, now: &NowFn<'_>, wait: &WaitFn<'_>, interrupt: InterruptWait) -> Result<(), ServeError> {
    let stop = serving(settings_file, max_rounds, now, wait, interrupt)
        .await
        .map_err(ServeError::Failed)?;
    match stop {
        Stop::Interrupted => Ok(()),
        Stop::Capped(end) => {
            let rounds = end.rounds;
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
    start(Path::new(settings_file), MAX_ROUNDS, &system_now, &pause, interrupt).await
}
