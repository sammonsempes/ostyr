use alerts::error::StoreError;
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
use response_playbooks::bundle::{open_playbooks, PlaybookSettings};
use response_playbooks::error::RoundError;
use response_playbooks::service::{open_service_settings, run_round, serve, Live, Outcome, ROUND_KEYS};
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::stdout;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;


const USAGE: &str = "usage: playbooks_service <settings.yaml>";


const DEADLINE: Duration = Duration::from_secs(30);


const DEBOUNCE: Duration = Duration::from_millis(300);


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


async fn run(settings_file: &Path) -> Result<(), Box<dyn Error>> {
    let settings_engine_audit_log = Arc::new(open_file_log(&response_playbooks::service::load_settings(settings_file)?.audit_file)?);
    let reload_audit = |shared: &Arc<_>| -> Arc<SharedAuditFn> {
        let owned = Arc::clone(shared);
        Arc::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
    };
    let settings_engine = Arc::new(open_service_settings(
        settings_file,
        Box::new({
            let audit = reload_audit(&settings_engine_audit_log);
            move |entry| audit(entry)
        }),
    )?);
    let start = current_config(&settings_engine);
    let bundle_engine = Arc::new(open_playbooks(PlaybookSettings {
        catalogue_path: start.catalogue.clone(),
        inventory_path: start.inventory.clone(),
        playbook_paths: start.playbooks.clone(),
        audit: reload_audit(&settings_engine_audit_log),
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
    migrate(&connect(&pg_settings).await?, ALERT_NAMESPACE, &ALERT_MIGRATIONS, DEADLINE).await?;
    let tenant = Arc::new(tenant_scope(&start.tenant)?);
    let live = || Live {
        bundle: current_config(&bundle_engine),
        settings: current_config(&settings_engine),
    };
    let mut next_round = |snapshot: Live| {
        one_round(
            Arc::clone(&pg_settings),
            Arc::clone(&tenant),
            Arc::clone(&settings_engine_audit_log),
            snapshot,
        )
    };
    serve(ROUNDS, &live, &mut next_round, pause).await;
    Ok(())
}


async fn one_round(pg: Arc<PgSettings>, scope: Arc<TenantScope>, log: Arc<AuditLog<File>>, snapshot: Live) -> Result<Outcome, RoundError> {
    let client = connect(&pg).await.map_err(StoreError::Pg)?;
    let exec = pg_executor(&client, DEADLINE);
    let audit = |entry| append_declared(&log, entry, &ROUND_KEYS).map(|_record| ());
    run_round(&exec, &scope, &snapshot, &audit, OffsetDateTime::now_utc, &mut stdout()).await
}


fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings_file] => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run(Path::new(settings_file))),
        _ => Err(USAGE.into()),
    }
}
