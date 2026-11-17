use core_audit::log::{append, open_file_log};
use core_config::reload::{current_config, ReloadContext};
use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::parse_settings;
use hunt_packs::clock::Reading;
use hunt_packs::model::HuntPack;
use hunt_packs::run::{run_pack, RunError};
use hunt_packs::schedule::due_runs;
use hunt_packs::service::{run_service, SettingsSource};
use hunt_packs::settings::open_hunt;
use hunt_packs::store::{Param, MIGRATIONS, MIGRATION_DEADLINE, MIGRATION_NAMESPACE, STATEMENT_DEADLINE};
use hunt_packs::tick::Hooks;
use hunt_packs::types::SleepFuture;
use metric_alerts::fetch::{agent_for, load_fetch_settings, read_key};
use std::error::Error;
use std::io::{stderr, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: hunt_service <hunt.yaml>";


const FIRST_COLUMN: usize = 0;


const WORKER_THREADS: usize = 2;


const LOG_IGNORED_CRATE: &str = "tokio_postgres";


const UNBOUNDED_ROUNDS: u64 = u64::MAX;


async fn execute(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<i64>, PgError> {
    let boxed: Vec<Box<dyn ToSql + Sync>> = params
        .into_iter()
        .map(|param| -> Box<dyn ToSql + Sync> {
            match param {
                Param::Text(text) => Box::new(text),
                Param::Int(number) => Box::new(number),
            }
        })
        .collect();
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = scoped_query(client, &scope, sql, &refs, STATEMENT_DEADLINE).await?;
    rows.iter().map(|row| row.try_get(FIRST_COLUMN).map_err(reduce)).collect()
}


#[cfg(unix)]
async fn wait_for_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        () = async { terminate.recv().await; } => Ok(()),
        interrupted = tokio::signal::ctrl_c() => interrupted,
    }
}


#[cfg(not(unix))]
async fn wait_for_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}


async fn scenario(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [hunt_file] = args else { Err(USAGE)? };
    let audit_log = open_file_log(&PathBuf::from(hunt_file).with_extension("audit"))?;
    let context = ReloadContext {
        actor_id: "hunt_service".to_owned(),
        tenant: "example".to_owned(),
        module: "hunt-packs".to_owned(),
        target: hunt_file.clone(),
        request_id: "hunt-reload".to_owned(),
    };
    let engine = open_hunt(PathBuf::from(hunt_file), Box::new(move |entry| append(&audit_log, entry)), context)?;
    let started = current_config(&engine);
    let client = {
        let settings = parse_settings(
            &std::fs::read_to_string(&started.pg_settings)?,
            &started.pg_settings.display().to_string(),
        )?;
        connect(&settings).await?
    };
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, MIGRATION_DEADLINE).await?;
    let mut exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| execute(&client, scope.clone(), sql, params);
    let mut runner = |pack: &HuntPack, tenant: &str, end: i64| {
        let fetch_settings = load_fetch_settings(Path::new(&current_config(&engine).clickhouse_settings)).map_err(|_| RunError::Window)?;
        let agent = agent_for(&fetch_settings).map_err(|_| RunError::Window)?;
        let password = read_key(&fetch_settings).map_err(|_| RunError::Window)?;
        let seconds = u64::try_from(end).map_err(|_| RunError::Window)?;
        run_pack(
            &agent,
            &fetch_settings,
            &password,
            pack,
            tenant,
            seconds,
            Duration::from_millis(fetch_settings.timeout_ms),
        )
    };
    let mut hooks = Hooks {
        run: &mut runner,
        due: due_runs,
    };
    let origin = Instant::now();
    let mut clock = || Reading {
        wall: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)),
        mono: i64::try_from(origin.elapsed().as_secs()).unwrap_or(i64::MAX),
    };
    let mut sleep = |seconds: u64| -> SleepFuture { Box::pin(tokio::time::sleep(Duration::from_secs(seconds))) };
    let (stop_tx, mut stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(error) = wait_for_signal().await {
            tracing::error!("signal handler failed: {error}");
        }
        if stop_tx.send(true).is_err() {
            tracing::error!("service already stopped");
        }
    });
    let source = SettingsSource {
        engine: &engine,
        path: Path::new(&hunt_file),
    };
    let report = run_service(&source, &mut clock, &mut sleep, &mut stop_rx, UNBOUNDED_ROUNDS, &mut exec, &mut hooks).await;
    tracing::info!("{report:?}");
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    tracing::dispatcher::set_global_default(tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(stderr).finish()))
        .map_err(std::io::Error::other)?;
    tracing_log::LogTracer::builder()
        .ignore_crate(LOG_IGNORED_CRATE)
        .init()
        .map_err(std::io::Error::other)?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()?;
    match runtime.block_on(scenario(&args)) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
