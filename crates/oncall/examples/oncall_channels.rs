//! Usage: oncall_channels <pg.yaml> <tenant> <channel-dir>. Loads every `*.yaml` channel of the directory; a refused one is printed, each loaded one records a sent notification for one alert.

use chrono::{DateTime, Utc};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use oncall::alert::{Cell, Outcome, Param, Statement};
use oncall::channel::load_channel;
use oncall::error::StoreError;
use oncall::store::{open_alert, record_notification, MIGRATIONS, MIGRATION_NAMESPACE};
use oncall::types::Row;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: oncall_channels <pg.yaml> <tenant> <channel-dir>";


const DEADLINE: Duration = Duration::from_secs(30);


fn bound(params: &[Param]) -> Vec<Box<dyn ToSql + Sync>> {
    params
        .iter()
        .map(|param| -> Box<dyn ToSql + Sync> {
            match param {
                Param::Int(value) => Box::new(*value),
                Param::Text(value) => Box::new(value.clone()),
                Param::OptText(value) => Box::new(value.clone()),
                Param::Time(value) => Box::new(*value),
            }
        })
        .collect()
}


fn cell_of(row: &tokio_postgres::Row, index: usize) -> Result<Cell, StoreError> {
    let column = row.columns().get(index).ok_or(StoreError::BadRow { column: "cell" })?;
    let cell = match column.type_().name() {
        "int8" => row.try_get(index).map(Cell::Int),
        "bool" => row.try_get(index).map(Cell::Bool),
        "timestamptz" => row.try_get::<_, Option<DateTime<Utc>>>(index).map(Cell::Time),
        _ => row.try_get(index).map(Cell::Text),
    };
    cell.map_err(|_error| StoreError::BadRow { column: "cell" })
}


async fn execute(client: &Client, scope: TenantScope, statement: Statement) -> Result<Vec<Row>, StoreError> {
    let boxed = bound(&statement.params);
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = scoped_query(client, &scope, statement.sql, &refs, DEADLINE).await?;
    rows.iter().map(|row| (0..row.len()).map(|index| cell_of(row, index)).collect()).collect()
}


async fn scenario(settings_file: &Path, tenant: &str, directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let scope = tenant_scope(tenant)?;
    let mut exec = |target: &TenantScope, statement: Statement| execute(&client, target.clone(), statement);
    let now = Utc::now();
    let opened = open_alert(&mut exec, &scope, "channel-proof", now).await?;
    let mut paths: Vec<_> = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|found| found.path()))
        .collect::<Result<_, _>>()?;
    paths.sort();
    let mut out = stdout();
    for path in paths {
        match load_channel(&path) {
            Err(error) => writeln!(out, "refused {}: {error}", path.display())?,
            Ok(channel) => {
                let seq = record_notification(&mut exec, &scope, opened.alert.id, &channel.name, &Outcome::Sent, now).await?;
                writeln!(out, "loaded {} and recorded notification {seq}", channel.name)?;
            }
        }
    }
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, tenant, directory] => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), tenant, Path::new(directory))) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        _ => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
