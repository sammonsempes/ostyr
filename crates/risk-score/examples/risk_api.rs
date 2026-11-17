//! Usage: risk_api <module.yaml> <weights.yaml>. Serves `GET /risk/entities` and `GET /risk/entities/{kind}/{id}` through core-api; `settings.pg_settings` names the core-pg file.

use alerts::backend::{LOG_IGNORED_CRATE, MAX_CONNECTIONS};
use alerts::settings::{api_startup_reloads, module_audit, open_pg_engine_from, SETTING_PG};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::logging::reloadable_dispatch;
use core_api::server::{new_listener, run_loaded, stop_listener};
use core_api::types::{SharedListener, StartupReloadFn};
use core_config::load::load_module;
use core_config::reload::{open_engine, reload, ReloadContext};
#[cfg(unix)]
use core_config::signal::reload_on_signals;
use core_config::watch::watch_files;
use risk_score::api::{risk_access, risk_document, risk_router};
use risk_score::backend::{pg_backend, system_clock, ACTOR};
use risk_score::cache::risk_state;
use risk_score::weights::{weights_loader, weights_state};
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


const WEIGHTS_ARGUMENT: usize = 1;


const STARTUP_REQUEST: &str = "startup";


const USAGE: &str = "usage: risk_api <module.yaml> <weights.yaml>";


async fn stop_on_interrupt(listener: SharedListener) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => stop_listener(&listener, Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let weights_file = PathBuf::from(arguments.get(WEIGHTS_ARGUMENT).ok_or(USAGE)?);
    let (dispatch, log) = reloadable_dispatch(BoxMakeWriter::new(stdout), DEFAULT_LOG_LEVEL);
    tracing::dispatcher::set_global_default(dispatch)?;
    tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;
    let loaded = load_module(Path::new(module_file))?;
    let listener = new_listener();
    let (opened, pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, listener.clone(), ACTOR)?;
    let engine = Arc::new(opened);
    let context = ReloadContext {
        actor_id: ACTOR.to_owned(),
        tenant: loaded.tenant.clone().unwrap_or_else(|| alerts::settings::DEFAULT_TENANT.to_owned()),
        module: loaded.name.clone(),
        target: weights_file.display().to_string(),
        request_id: STARTUP_REQUEST.to_owned(),
    };
    let weights = Arc::new(open_engine(
        weights_loader(weights_file.clone()),
        weights_state,
        Vec::new(),
        module_audit(listener.clone()),
        context,
    )?);
    let _watch = watch_files(Arc::clone(&engine), &[PathBuf::from(module_file), pg_file], RELOAD_DEBOUNCE)?;
    let _weights_watch = watch_files(Arc::clone(&weights), &[weights_file], RELOAD_DEBOUNCE)?;
    #[cfg(unix)]
    let _signals = reload_on_signals(Arc::clone(&engine), &[signal_hook::consts::SIGHUP])?;
    #[cfg(unix)]
    let _weights_signals = reload_on_signals(Arc::clone(&weights), &[signal_hook::consts::SIGHUP])?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(stop_on_interrupt(listener.clone()));
    let mut startup_reloads = api_startup_reloads(Arc::clone(&engine));
    let startup_weights = Arc::clone(&weights);
    startup_reloads.push(Box::new(move || reload(&startup_weights)) as StartupReloadFn);
    let state = risk_state(pg_backend(engine, permits), weights, system_clock());
    run_loaded(
        Path::new(module_file),
        loaded,
        (risk_router(state), risk_access(), vec![risk_document()]),
        &[SETTING_PG],
        listener,
        Some(log),
        startup_reloads,
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
