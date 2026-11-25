//! The `ostyr-playbooks` service: the dry-run rounds over the alert feed until the interrupt wait resolves; logs on stderr, traces on stdout.


use crate::bundle::{open_playbooks, PlaybookSettings};
use crate::error::RoundError;
use crate::runs::{MIGRATIONS as RUNS_MIGRATIONS, MIGRATION_NAMESPACE as RUNS_NAMESPACE};
use crate::service::{load_settings, open_service_settings_from, run_round, serve, Db, Live, Outcome, Replays, ROUND_KEYS};
use crate::types::{ControlFuture, InterruptWait, MigrateFn, MigrationRun, WaitFn};
use alerts::backend::LOG_IGNORED_CRATE;
use alerts::error::StoreError;
use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use core_pg::transaction::cross;
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::{stderr, stdout};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, warn};


const USAGE: &str = "usage: ostyr-playbooks <settings.yaml>";


const DEBOUNCE: Duration = Duration::from_millis(300);


const SEARCH_PATH_ATTEMPTS: usize = 10;


const SEARCH_PATH_PAUSE: Duration = Duration::from_secs(2);


const ROUNDS: usize = usize::MAX;


fn pause(duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


#[cfg(unix)]
fn keep_signals<Config: Send + Sync + 'static>(engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(Arc::clone(engine), &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
fn keep_signals<Config>(_engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<NoSignals> {
    Ok(NoSignals)
}


pub async fn run(arguments: &[String], interrupt: InterruptWait) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).finish())?;
    tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;
    start(Path::new(settings_file), ROUNDS, interrupt).await
}


pub fn shared_reload_audit(log: &Arc<AuditLog<File>>) -> Arc<SharedAuditFn> {
    let owned = Arc::clone(log);
    Arc::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


pub async fn start(settings_file: &Path, rounds: usize, interrupt: InterruptWait) -> Result<(), Box<dyn Error>> {
    let baseline = load_settings(settings_file)?;
    let settings_engine_audit_log = Arc::new(open_file_log(&baseline.audit_file)?);
    let settings_engine = Arc::new(open_service_settings_from(
        settings_file,
        baseline,
        boxed_reload_audit(&settings_engine_audit_log),
    )?);
    let start = current_config(&settings_engine);
    let bundle_engine = Arc::new(open_playbooks(PlaybookSettings {
        catalogue_path: start.catalogue.clone(),
        inventory_path: start.inventory.clone(),
        playbook_paths: start.playbooks.clone(),
        audit: shared_reload_audit(&settings_engine_audit_log),
    })?);
    let bundle_files: Vec<PathBuf> = [start.catalogue.clone(), start.inventory.clone()]
        .into_iter()
        .chain(start.playbooks.clone())
        .collect();
    let _bundle_watch = watch_files(Arc::clone(&bundle_engine), &bundle_files, DEBOUNCE)?;
    let _settings_watch = watch_files(Arc::clone(&settings_engine), &[settings_file.to_path_buf()], DEBOUNCE)?;
    let _bundle_signals = keep_signals(&bundle_engine)?;
    let _settings_signals = keep_signals(&settings_engine)?;
    let pg_settings = Arc::new(load_pg_settings(&start.pg_settings)?);
    migrate_retrying(alerts_migration, &pg_settings, pause).await?;
    migrate_retrying(runs_migration, &pg_settings, pause).await?;
    let tenant = Arc::new(tenant_scope(&start.tenant)?);
    let live = || Live {
        bundle: current_config(&bundle_engine),
        settings: current_config(&settings_engine),
    };
    let replays = Arc::new(Mutex::new(Replays::default()));
    let mut next_round = |snapshot: Live| {
        one_round(
            Arc::clone(&pg_settings),
            Arc::clone(&tenant),
            Arc::clone(&settings_engine_audit_log),
            Arc::clone(&replays),
            snapshot,
        )
    };
    info!(tenant = start.tenant, "serving");
    tokio::select! {
        biased;
        waited = interrupt => Ok(waited?),
        () = serve(rounds, &live, &mut next_round, pause) => Ok(()),
    }
}


pub fn alerts_migration(settings: Arc<PgSettings>) -> MigrationRun {
    Box::pin(async move {
        let client = connect(&settings).await?;
        migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, statement_deadline(&settings)).await
    })
}


pub fn runs_migration(settings: Arc<PgSettings>) -> MigrationRun {
    Box::pin(async move {
        let client = connect(&settings).await?;
        migrate(&client, RUNS_NAMESPACE, &RUNS_MIGRATIONS, statement_deadline(&settings)).await
    })
}


/// Only the function search path check is retried: the platform may be between two of its migrations; any other error ends the start.
pub async fn migrate_retrying(attempt_migration: MigrateFn, settings: &Arc<PgSettings>, wait: WaitFn) -> Result<Vec<String>, PgError> {
    let mut retries = 0;
    let mut result = attempt_migration(Arc::clone(settings)).await;
    while matches!(result, Err(PgError::FunctionSearchPath { .. })) && retries < SEARCH_PATH_ATTEMPTS {
        retries += 1;
        warn!(attempt = retries, "search path check failed, retrying");
        wait(SEARCH_PATH_PAUSE).await;
        result = attempt_migration(Arc::clone(settings)).await;
    }
    result
}


/// The deadline of every statement is the core-pg `statement_timeout_secs` setting.
fn statement_deadline(settings: &PgSettings) -> Duration {
    Duration::from_secs(settings.statement_timeout_secs)
}


async fn one_round(
    pg: Arc<PgSettings>,
    scope: Arc<TenantScope>,
    log: Arc<AuditLog<File>>,
    replays: Arc<Mutex<Replays>>,
    snapshot: Live,
) -> Result<Outcome, RoundError> {
    let client = connect(&pg).await.map_err(StoreError::Pg)?;
    let deadline = statement_deadline(&pg);
    let exec = pg_executor(&client, deadline);
    let control = |boundary| -> ControlFuture<'_> { Box::pin(cross(&client, boundary, deadline)) };
    let db = Db {
        exec: &exec,
        control: &control,
    };
    let audit = |entry| append_declared(&log, entry, &ROUND_KEYS).map(|_record| ());
    let mut state = replays.lock().await;
    run_round(&db, &scope, &snapshot, &audit, OffsetDateTime::now_utc, &mut stdout(), &mut state).await
}
