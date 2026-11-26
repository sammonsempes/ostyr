//! The `ostyr-hunt` service: the scheduler rounds until the interrupt wait resolves; logs on stderr, the `log` crate bridge is not installed.


use crate::backend::execute;
use crate::clock::Reading;
use crate::model::HuntPack;
use crate::run::{run_pack, HuntOutcome, RunError};
use crate::schedule::due_runs;
use crate::service::{run_service, ServiceReport, SettingsSource};
use crate::settings::{open_hunt_from, HuntSettings, HuntSettingsError};
use crate::stat_model::{stat_pack, StatHunt};
use crate::stat_run::run_stat;
use crate::store::{Param, MIGRATIONS, MIGRATION_DEADLINE, MIGRATION_NAMESPACE};
use crate::tick::Hooks;
use crate::types::{InterruptWait, ReaderRunFn, SleepFuture};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::tenant::AUDIT_TENANT;
use core_config::load::load_file;
use core_config::reload::{current_config, ReloadContext, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::TenantScope;
use core_pg::settings::load_settings;
use metric_alerts::fetch::{agent_for, load_fetch_settings, read_key, FetchError};
use std::error::Error;
use std::fs::File;
use std::io::stderr;
use std::path::Path;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch::{self, Sender};
use tracing::{error, info, warn};


const USAGE: &str = "usage: ostyr-hunt <hunt.yaml>";


const WORKER_THREADS: usize = 2;


const UNBOUNDED_ROUNDS: u64 = u64::MAX;


/// Two workers: the blocking pack run holds one thread while the other still sees the signal.
pub fn runtime() -> std::io::Result<Runtime> {
    Builder::new_multi_thread().worker_threads(WORKER_THREADS).enable_all().build()
}


#[cfg(unix)]
pub async fn wait_for_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        () = async { terminate.recv().await; } => Ok(()),
        interrupted = tokio::signal::ctrl_c() => interrupted,
    }
}


#[cfg(not(unix))]
pub async fn wait_for_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}


pub fn setup_failed(failure: FetchError) -> RunError {
    let text = failure.to_string();
    warn!("hunt run setup failed: {text}");
    RunError::Window
}


/// One run: the ClickHouse settings and the key are read again, so a changed path applies live; `run` gets the agent, settings, key, window end and time left.
pub fn run_with_reader(clickhouse_settings: &Path, end: i64, run: &ReaderRunFn<'_>) -> Result<HuntOutcome, RunError> {
    let fetch_settings = load_fetch_settings(clickhouse_settings).map_err(setup_failed)?;
    let agent = agent_for(&fetch_settings).map_err(setup_failed)?;
    let password = read_key(&fetch_settings).map_err(setup_failed)?;
    let seconds = u64::try_from(end).map_err(|_| RunError::Window)?;
    run(
        &agent,
        &fetch_settings,
        &password,
        seconds,
        Duration::from_millis(fetch_settings.timeout_ms),
    )
}


/// One pack run.
pub fn run_one(clickhouse_settings: &Path, pack: &HuntPack, tenant: &str, end: i64) -> Result<HuntOutcome, RunError> {
    run_with_reader(clickhouse_settings, end, &|agent, settings, password, seconds, remaining| {
        run_pack(agent, settings, password, pack, tenant, seconds, remaining)
    })
}


/// The statistical hunt the pack stands for, if any: the pack must equal the hunt's own scheduling view.
pub fn stat_hunt_of<'hunts>(hunts: &'hunts [StatHunt], pack: &HuntPack) -> Option<&'hunts StatHunt> {
    hunts.iter().find(|hunt| stat_pack(hunt) == *pack)
}


/// A statistical hunt runs through `run_stat`, any other pack through `run_pack`.
pub fn run_either(settings: &HuntSettings, pack: &HuntPack, tenant: &str, end: i64) -> Result<HuntOutcome, RunError> {
    match stat_hunt_of(&settings.stat_hunts, pack) {
        Some(hunt) => run_with_reader(&settings.clickhouse_settings, end, &|agent, fetch, password, seconds, remaining| {
            run_stat(agent, fetch, password, hunt, tenant, seconds, remaining)
        }),
        None => run_one(&settings.clickhouse_settings, pack, tenant, end),
    }
}


pub fn read_clock(origin: Instant) -> Reading {
    Reading {
        wall: OffsetDateTime::now_utc().unix_timestamp(),
        mono: i64::try_from(origin.elapsed().as_secs()).unwrap_or(i64::MAX),
    }
}


pub async fn forward_interrupt(wait: InterruptWait, stop: Sender<bool>) {
    if let Err(failure) = wait.await {
        error!("signal handler failed: {failure}");
    }
    if stop.send(true).is_err() {
        error!("service already stopped");
    }
}


pub fn boxed_reload_audit(log: AuditLog<File>) -> Box<SharedAuditFn> {
    Box::new(move |entry| append_declared(&log, entry, &RELOAD_DECLARED_KEYS))
}


pub async fn serve_hunt(arguments: &[String], interrupt: InterruptWait) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).finish())?;
    let report = start(Path::new(settings_file), UNBOUNDED_ROUNDS, interrupt).await?;
    info!("{report:?}");
    Ok(())
}


/// The audit identity of a reload: the tenant is the non-customer `all`, the diff lists every tenant of the service.
pub fn reload_context(hunt_file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: "ostyr-hunt".to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: "hunt-packs".to_owned(),
        target: hunt_file.display().to_string(),
        request_id: "hunt-reload".to_owned(),
    }
}


pub async fn start(hunt_file: &Path, rounds: u64, interrupt: InterruptWait) -> Result<ServiceReport, Box<dyn Error>> {
    let first = load_file::<HuntSettings>(hunt_file)?;
    start_from(hunt_file, first, rounds, interrupt).await
}


/// The service from the one read of the settings file: that value is the audit path and the engine baseline.
pub async fn start_from(hunt_file: &Path, first: HuntSettings, rounds: u64, interrupt: InterruptWait) -> Result<ServiceReport, Box<dyn Error>> {
    first.audit_file.is_absolute().then_some(()).ok_or(HuntSettingsError::AuditFile)?;
    let audit_log = open_file_log(&first.audit_file)?;
    let context = reload_context(hunt_file);
    let engine = open_hunt_from(hunt_file.to_path_buf(), first, boxed_reload_audit(audit_log), context)?;
    let started = current_config(&engine);
    let client = connect(&load_settings(&started.pg_settings)?).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, MIGRATION_DEADLINE).await?;
    let mut exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| execute(&client, scope.clone(), sql, params);
    let mut runner = |pack: &HuntPack, tenant: &str, end: i64| run_either(&current_config(&engine), pack, tenant, end);
    let mut hooks = Hooks {
        run: &mut runner,
        due: due_runs,
    };
    let origin = Instant::now();
    let mut clock = || read_clock(origin);
    let mut sleep = |seconds: u64| -> SleepFuture { Box::pin(tokio::time::sleep(Duration::from_secs(seconds))) };
    let (stop_tx, mut stop_rx) = watch::channel(false);
    tokio::spawn(forward_interrupt(interrupt, stop_tx));
    let source = SettingsSource {
        engine: &engine,
        path: hunt_file,
    };
    info!("serving");
    Ok(run_service(&source, &mut clock, &mut sleep, &mut stop_rx, rounds, &mut exec, &mut hooks).await)
}
