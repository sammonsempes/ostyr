use chrono::{DateTime, Utc};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use oncall::alert::{Cell, Event, Param, Statement};
use oncall::error::StoreError;
use oncall::limits::MAX_OPEN_ALERTS;
use oncall::store::{apply_event, open_alert, open_alerts, run, MIGRATIONS, UPDATE_SQL};
use oncall::types::Row;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: oncall_store <pg.yaml> <tenant-a> <tenant-b>";


const DEADLINE: Duration = Duration::from_secs(30);


const STALE_VERSION: i64 = 0;


const COLUMN_ID: usize = 0;


const COLUMN_STATE: usize = 1;


const COLUMN_LEVEL: usize = 2;


const COLUMN_OCCURRENCES: usize = 3;


const COLUMN_VERSION: usize = 4;


const COLUMN_FINGERPRINT: usize = 5;


const DUMP_SQL: &str = "SELECT id, state, level, occurrences, version, fingerprint FROM oncall_alerts WHERE tenant = $1 ORDER BY id";


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


async fn dump(client: &Client, scope: &TenantScope, out: &mut impl Write) -> Result<(), Box<dyn std::error::Error>> {
    let rows = scoped_query(client, scope, DUMP_SQL, &[], DEADLINE).await?;
    rows.iter().try_for_each(|row| {
        writeln!(
            out,
            "id={} state={} level={} occurrences={} version={} fingerprint={}",
            row.try_get::<_, i64>(COLUMN_ID)?,
            row.try_get::<_, String>(COLUMN_STATE)?,
            row.try_get::<_, i64>(COLUMN_LEVEL)?,
            row.try_get::<_, i64>(COLUMN_OCCURRENCES)?,
            row.try_get::<_, i64>(COLUMN_VERSION)?,
            row.try_get::<_, String>(COLUMN_FINGERPRINT)?
        )?;
        Ok(())
    })
}


async fn scenario(settings_file: &Path, tenant_a: &str, tenant_b: &str) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    let applied = migrate(&client, &MIGRATIONS, DEADLINE).await?;
    let mut out = stdout();
    writeln!(out, "migrations applied: {applied:?}")?;
    let scope_a = tenant_scope(tenant_a)?;
    let scope_b = tenant_scope(tenant_b)?;
    let mut exec = |scope: &TenantScope, statement: Statement| execute(&client, scope.clone(), statement);
    let now = Utc::now();
    let first = open_alert(&mut exec, &scope_a, "cpu-high", now).await?;
    let second = open_alert(&mut exec, &scope_a, "cpu-high", now).await?;
    let foreign = open_alert(&mut exec, &scope_b, "cpu-high", now).await?;
    writeln!(
        out,
        "A first created={} A second created={} occurrences={} B created={}",
        first.created, second.created, second.alert.occurrences, foreign.created
    )?;
    let id = first.alert.id;
    apply_event(&mut exec, &scope_a, id, Event::Acknowledge, now).await?;
    apply_event(&mut exec, &scope_a, id, Event::Escalate { to_level: 1 }, now).await?;
    let stale = run(
        &mut exec,
        &scope_a,
        UPDATE_SQL,
        vec![
            Param::Int(id),
            Param::Text("resolved".to_owned()),
            Param::Int(0),
            Param::Time(None),
            Param::Time(Some(now)),
            Param::Int(STALE_VERSION),
        ],
    )
    .await?;
    writeln!(out, "stale update affected {} row(s): the typed outcome is Conflict", stale.len())?;
    apply_event(&mut exec, &scope_a, id, Event::Resolve, now).await?;
    let reopened = open_alert(&mut exec, &scope_a, "cpu-high", now).await?;
    writeln!(out, "reopened created={} new id differs={}", reopened.created, reopened.alert.id != id)?;
    let live = open_alerts(&mut exec, &scope_a, MAX_OPEN_ALERTS).await?;
    writeln!(out, "tenant A live alerts: {}", live.len())?;
    writeln!(out, "-- tenant A rows")?;
    dump(&client, &scope_a, &mut out).await?;
    writeln!(out, "-- tenant B rows")?;
    dump(&client, &scope_b, &mut out).await
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, tenant_a, tenant_b] => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), tenant_a, tenant_b)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        _ => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
