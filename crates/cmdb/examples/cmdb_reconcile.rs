//! Usage: cmdb_reconcile <module.yaml> <tenant> <source> <serial>. Runs `reconcile_with_alerts` for one serial number against the PostgreSQL of `settings.pg_settings`.

use alerts::backend::{lease, MAX_CONNECTIONS};
use alerts::settings::open_pg_engine_from;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use cmdb::alerting::reconcile_with_alerts;
use cmdb::backend::ACTOR;
use cmdb::model::{AssetKind, IdentityKey, Limits, Observation};
use cmdb::pg::pg_executor;
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_config::load::load_module;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;


const SOURCE_INDEX: usize = 2;


const SERIAL_INDEX: usize = 3;


const USAGE: &str = "usage: cmdb_reconcile <module.yaml> <tenant> <source> <serial>";


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let tenant = arguments.get(1).ok_or(USAGE)?;
    let source = arguments.get(SOURCE_INDEX).ok_or(USAGE)?;
    let serial = arguments.get(SERIAL_INDEX).ok_or(USAGE)?;
    let loaded = load_module(Path::new(module_file))?;
    let (opened, _pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, core_api::server::new_listener(), ACTOR)?;
    let engine = Arc::new(opened);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let held = lease(&engine, &permits).await?;
    migrate(&held.client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, held.deadline).await?;
    migrate(&held.client, MIGRATION_NAMESPACE, &MIGRATIONS, held.deadline).await?;
    let observation = Observation {
        source: source.clone(),
        kind: AssetKind::Server,
        keys: [(IdentityKey::SerialNumber, serial.clone())].into_iter().collect(),
        attributes: Default::default(),
    };
    let executor = pg_executor(&held.client, held.deadline);
    let now_micros = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let scope = tenant_scope(tenant)?;
    let (stored, counts) = reconcile_with_alerts(&executor, &scope, &observation, &Default::default(), &Limits::default(), now_micros).await?;
    writeln!(stdout(), "stored: events {:?}", stored.outcome.events)?;
    writeln!(stdout(), "alerts: {counts:?}")?;
    Ok(())
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "refused: {error}").map(|()| ExitCode::FAILURE),
    }
}
