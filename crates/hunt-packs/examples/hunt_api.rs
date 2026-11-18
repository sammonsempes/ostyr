//! Usage: hunt_api <module.yaml>. Serves `GET /hunts/findings` through core-api; `settings.pg_settings` names the core-pg settings file.

use alerts::backend::{LOG_IGNORED_CRATE, MAX_CONNECTIONS};
use alerts::settings::{api_startup_reloads, open_pg_engine_from, SETTING_PG};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::logging::reloadable_dispatch;
use core_api::server::{new_listener, run_loaded, stop_listener};
use core_api::types::SharedListener;
use core_config::load::load_module;
use core_config::reload::{current_config, ReloadEngine};
#[cfg(unix)]
use core_config::signal::reload_on_signals;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use hunt_packs::api::{hunts_access, hunts_document, hunts_router, permit_backend, read_findings};
use hunt_packs::api_model::{FindingsQuery, FindingsReply};
use hunt_packs::error::FindingsError;
use hunt_packs::store::{FindingRow, Param, StateError, MIGRATIONS, MIGRATION_DEADLINE, MIGRATION_NAMESPACE, STATEMENT_DEADLINE};
use hunt_packs::types::FindingsFn;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Row};
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


const RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);


const USAGE: &str = "usage: hunt_api <module.yaml>";


const ACTOR: &str = "hunts";


const FIRST_COLUMN: usize = 0;


const SECOND_COLUMN: usize = 1;


const THIRD_COLUMN: usize = 2;


const FOURTH_COLUMN: usize = 3;


const FIFTH_COLUMN: usize = 4;


async fn query_rows(client: &Client, scope: &TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<Row>, PgError> {
    let boxed: Vec<Box<dyn ToSql + Sync + Send>> = params
        .into_iter()
        .map(|param| -> Box<dyn ToSql + Sync + Send> {
            match param {
                Param::Text(text) => Box::new(text),
                Param::Int(number) => Box::new(number),
            }
        })
        .collect();
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    scoped_query(client, scope, sql, &refs, STATEMENT_DEADLINE).await
}


async fn execute(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<i64>, PgError> {
    let rows = query_rows(client, &scope, sql, params).await?;
    rows.iter().map(|row| row.try_get(FIRST_COLUMN).map_err(reduce)).collect()
}


fn finding_row(row: &Row) -> Result<FindingRow, PgError> {
    Ok(FindingRow {
        pack_id: row.try_get(FIRST_COLUMN).map_err(reduce)?,
        window_start: row.try_get(SECOND_COLUMN).map_err(reduce)?,
        window_end: row.try_get(THIRD_COLUMN).map_err(reduce)?,
        matches: row.try_get(FOURTH_COLUMN).map_err(reduce)?,
        max_matches: row.try_get(FIFTH_COLUMN).map_err(reduce)?,
    })
}


async fn execute_list(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<FindingRow>, PgError> {
    let rows = query_rows(client, &scope, sql, params).await?;
    rows.iter().map(finding_row).collect()
}


async fn read_pg(engine: Arc<ReloadEngine<PgSettings>>, scope: TenantScope, query: FindingsQuery) -> Result<FindingsReply, FindingsError> {
    let settings = current_config(&engine);
    let client = connect(&settings).await.map_err(StateError::from)?;
    let mut list_exec = |bound: &TenantScope, sql: &'static str, params: Vec<Param>| execute_list(&client, bound.clone(), sql, params);
    let mut count_exec = |bound: &TenantScope, sql: &'static str, params: Vec<Param>| execute(&client, bound.clone(), sql, params);
    read_findings(&mut list_exec, &mut count_exec, &scope, &query).await
}


fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> FindingsFn {
    let reading: FindingsFn = Arc::new(move |scope, query| Box::pin(read_pg(Arc::clone(&engine), scope, query)));
    permit_backend(permits, reading)
}


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
    let client = connect(&current_config(&engine)).await?;
    let applied = migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, MIGRATION_DEADLINE).await?;
    drop(client);
    tracing::info!(applied = applied.len(), "hunt migrations checked");
    tokio::spawn(stop_on_interrupt(listener.clone()));
    let startup_engine = Arc::clone(&engine);
    run_loaded(
        Path::new(module_file),
        loaded,
        (hunts_router(pg_backend(engine, permits)), hunts_access(), vec![hunts_document()]),
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
