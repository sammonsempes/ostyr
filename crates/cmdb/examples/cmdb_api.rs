//! Usage: cmdb_api <module.yaml>. Serves `GET /assets` and `GET /assets/{id}` through core-api; `settings.pg_settings` names the core-pg settings file.

use alerts::backend::{lease, LOG_IGNORED_CRATE, MAX_CONNECTIONS};
use alerts::settings::{api_startup_reloads, open_pg_engine_from, SETTING_PG};
use cmdb::api::{cmdb_access, cmdb_document, cmdb_router};
use cmdb::backend::pg_backend;
use cmdb::backend::ACTOR;
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::logging::reloadable_dispatch;
use core_api::server::{new_listener, run_loaded, stop_listener};
use core_api::types::SharedListener;
use core_config::load::load_module;
#[cfg(unix)]
use core_config::signal::reload_on_signals;
use core_config::watch::watch_files;
use core_pg::migrate::migrate;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


const RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);


const USAGE: &str = "usage: cmdb_api <module.yaml>";


async fn stop_on_interrupt(listener: SharedListener) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => stop_listener(&listener, Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let (dispatch, log) = reloadable_dispatch(BoxMakeWriter::new(stdout), DEFAULT_LOG_LEVEL);
    tracing::dispatcher::set_global_default(dispatch)?;
    tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;
    let loaded = load_module(Path::new(module_file))?;
    let listener = new_listener();
    let (opened, pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, listener.clone(), ACTOR)?;
    let engine = Arc::new(opened);
    let _watch = watch_files(Arc::clone(&engine), &[PathBuf::from(module_file), pg_file], RELOAD_DEBOUNCE)?;
    #[cfg(unix)]
    let _signals = reload_on_signals(Arc::clone(&engine), &[signal_hook::consts::SIGHUP])?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let held = lease(&engine, &permits).await?;
    let applied = migrate(&held.client, MIGRATION_NAMESPACE, &MIGRATIONS, held.deadline).await?;
    drop(held);
    tracing::info!(applied = applied.len(), "cmdb migrations checked");
    tokio::spawn(stop_on_interrupt(listener.clone()));
    let startup_engine = Arc::clone(&engine);
    run_loaded(
        Path::new(module_file),
        loaded,
        (cmdb_router(pg_backend(engine, permits)), cmdb_access(), vec![cmdb_document()]),
        &[SETTING_PG],
        listener,
        Some(log),
        api_startup_reloads(startup_engine),
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
