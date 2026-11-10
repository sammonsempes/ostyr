//! Usage: alerts_api <module.yaml>. Serves `GET /alerts` and `GET /alerts/{id}` through core-api; `settings.pg_settings` names the core-pg settings file.

use alerts::api::{alerts_access, alerts_document, alerts_router};
use alerts::backend::{lease, pg_backend, LOG_IGNORED_CRATE, MAX_CONNECTIONS};
use alerts::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::logging::reloadable_dispatch;
use core_api::server::{new_listener, run_module, stop_listener};
use core_api::types::SharedListener;
use core_audit::log::{append, genesis_log};
use core_config::reload::{module_loader, ReloadContext, ReloadEngine};
use core_pg::migrate::migrate;
use core_pg::settings::{open_settings, PgSettings};
use std::error::Error;
use std::io::{sink, stderr, stdout, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


const SETTING_PG: &str = "pg_settings";


const USAGE: &str = "usage: alerts_api <module.yaml>";


async fn stop_on_interrupt(listener: SharedListener) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => stop_listener(&listener, Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


fn open_pg(module_file: &str) -> Result<ReloadEngine<PgSettings>, Box<dyn Error>> {
    let module = module_loader(PathBuf::from(module_file))()?;
    let pg_file = PathBuf::from(module.settings.get(SETTING_PG).ok_or("settings.pg_settings is required")?);
    let context = ReloadContext {
        actor_id: "alerts".to_owned(),
        tenant: module.tenant.clone().unwrap_or_else(|| "default".to_owned()),
        module: module.name.clone(),
        target: pg_file.display().to_string(),
        request_id: "startup".to_owned(),
    };
    let log = genesis_log(sink());
    Ok(open_settings(pg_file, Box::new(move |entry| append(&log, entry)), context)?)
}


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let (dispatch, log) = reloadable_dispatch(BoxMakeWriter::new(stdout), DEFAULT_LOG_LEVEL);
    tracing::dispatcher::set_global_default(dispatch)?;
    tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;
    let engine = Arc::new(open_pg(module_file)?);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let held = lease(&engine, &permits).await?;
    let applied = migrate(&held.client, MIGRATION_NAMESPACE, &MIGRATIONS, held.deadline).await?;
    drop(held);
    tracing::info!(applied = applied.len(), "alerts migrations checked");
    let listener = new_listener();
    tokio::spawn(stop_on_interrupt(listener.clone()));
    run_module(
        arguments,
        alerts_router(pg_backend(engine, permits)),
        alerts_access(),
        vec![alerts_document()],
        listener,
        Some(log),
    )
    .await?;
    Ok(())
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
