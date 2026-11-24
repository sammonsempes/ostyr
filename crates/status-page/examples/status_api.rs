//! Usage: status_api <module.yaml> <server.yaml> <public-address>. Serves the incident write routes through core-api and, in the same process, the public page of `ostyr-status-page`.
use alerts::backend::{lease, LOG_IGNORED_CRATE, MAX_CONNECTIONS};
use alerts::settings::{api_startup_reloads, open_pg_engine_from, SETTING_PG};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::logging::reloadable_dispatch;
use core_api::server::{new_listener, run_loaded, stop_listener};
use core_api::types::SharedListener;
use core_config::load::{load_file, load_module};
#[cfg(unix)]
use core_config::signal::reload_on_signals;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::TenantScope;
use core_pg::settings::load_settings;
use status_page::api::{status_access, status_document, status_router};
use status_page::api_model::PageServices;
use status_page::app::{run_app_with, AppFile};
use status_page::backend::pg_backend;
use status_page::config::load_config;
use status_page::error::StoreError;
use status_page::model::DEFAULT_LIMITS;
use status_page::pg::execute;
use status_page::publish::declared_services;
use status_page::store::{read_published, MAX_PUBLISHED, MIGRATIONS, MIGRATION_NAMESPACE};
use status_page::store_model::{PublishedRead, Statement};
use status_page::types::IncidentReadFn;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const ACTOR: &str = "status-page";


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


const RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);


const PUBLIC_ADDRESS_ARGUMENT: usize = 2;


const USAGE: &str = "usage: status_api <module.yaml> <server.yaml> <public-address>";


async fn stop_on_interrupt(listener: SharedListener) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => stop_listener(&listener, Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


async fn read_once(pg_file: &Path, scope: &TenantScope, services: &[String]) -> Result<PublishedRead, StoreError> {
    let settings = load_settings(pg_file)?;
    let deadline = Duration::from_secs(settings.statement_timeout_secs);
    let client = connect(&settings).await?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&client, query_scope.clone(), statement, deadline);
    read_published(&mut exec, scope, services, MAX_PUBLISHED).await
}


fn pg_reader(pg_file: PathBuf) -> IncidentReadFn {
    Box::new(move |scope, services| {
        let path = pg_file.clone();
        Box::pin(async move { read_once(&path, &scope, &services).await })
    })
}


async fn public_page(file: AppFile, address: String) -> Result<(), Box<dyn Error + Send + Sync>> {
    let reader = file.pg_file.clone().map(pg_reader);
    let listener = TcpListener::bind(address).await?;
    let shutdown = Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot wait for the stop signal");
        }
    });
    Ok(run_app_with(file, listener, shutdown, reader).await?)
}


async fn serve_all(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let server_file = arguments.get(1).ok_or(USAGE)?;
    let public_address = arguments.get(PUBLIC_ADDRESS_ARGUMENT).ok_or(USAGE)?.clone();
    let (dispatch, log) = reloadable_dispatch(BoxMakeWriter::new(stdout), DEFAULT_LOG_LEVEL);
    tracing::dispatcher::set_global_default(dispatch)?;
    tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;
    let loaded = load_module(Path::new(module_file))?;
    let app_file: AppFile = load_file(Path::new(server_file))?;
    let page_config = load_config(&app_file.page_file, &DEFAULT_LIMITS)?;
    let page = Arc::new(PageServices {
        tenant: page_config.tenant.clone(),
        services: declared_services(&page_config).into_iter().collect(),
    });
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
    tracing::info!(applied = applied.len(), "status migrations checked");
    tokio::spawn(stop_on_interrupt(listener.clone()));
    tokio::spawn(async move {
        if let Err(error) = public_page(app_file, public_address).await {
            tracing::error!(%error, "the public page stopped");
        }
    });
    let startup_engine = Arc::clone(&engine);
    run_loaded(
        Path::new(module_file),
        loaded,
        (status_router(pg_backend(engine, permits, page)), status_access(), vec![status_document()]),
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
    match serve_all(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
