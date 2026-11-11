use alerts::id::alert_id;
use alerts::model::{Alert as SourceAlert, Severity, Summary};
use alerts::pg::pg_executor;
use alerts::store::{insert_alerts, MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use alerts::types::RowFuture;
use chrono::{DateTime, Utc};
use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use oncall::alert::{Cell, Param, Statement};
use oncall::alert_source::{parse_source_settings, purge_statements, run_rounds, Round, RoundHooks, SourceSettings, PURGE_SQL};
use oncall::error::StoreError;
use oncall::holder::process_holder;
use oncall::limits::PURGE_CLIENT_DEADLINE_MILLIS;
use oncall::link::os_random;
use oncall::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use oncall::types::{PurgedCounts, Row};
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: oncall_poller run <pg.yaml> <source.yaml> <label> | oncall_poller seed <pg.yaml> <tenant> <first-index> <count>";


const DEADLINE: Duration = Duration::from_secs(30);


const MILLIS_PER_SECOND: u64 = 1_000;


const SUMMARY_BYTES: u64 = 2;


const BASE_CREATED: u64 = 1_000;


const MAX_ROUNDS: usize = 100_000;


const WRITE_FAILED: &str = "stdout closed";


fn summary(round: &Round) -> String {
    let purged = round
        .purged
        .as_ref()
        .map_or_else(|error| error.to_string(), |counts| format!("{counts:?}"));
    let tenants: Vec<String> = round
        .outcomes
        .iter()
        .map(|(tenant, outcome)| {
            format!(
                "{tenant}={}",
                outcome.as_ref().map_or_else(
                    |error| error.to_string(),
                    |counts| format!(
                        "opened:{} already:{} conflict:{} skipped_backlog:{}",
                        counts.opened, counts.already, counts.conflict, counts.skipped_backlog
                    )
                )
            )
        })
        .collect();
    let leased = round.leased.as_ref().map_or_else(|error| error.to_string(), ToString::to_string);
    format!("leased={leased} purged={purged} {}", tenants.join(" "))
}


fn wall_clock() -> DateTime<Utc> {
    Utc::now()
}


fn source_alert(tenant: &str, index: u64) -> SourceAlert {
    let event_ids = vec![format!("event-{index}")];
    SourceAlert {
        id: alert_id(tenant, "rule", &event_ids),
        tenant: tenant.to_owned(),
        rule_id: "rule".to_owned(),
        rule_title: format!("<!channel> alert {index}"),
        severity: Severity::High,
        event_time: "2026-11-10T00:00:00Z".to_owned(),
        created_micros: BASE_CREATED + index,
        host_name: Some("web-1".to_owned()),
        user_name: None,
        event_ids,
        summary: Summary {
            text: "{}".to_owned(),
            truncated: false,
            original_bytes: SUMMARY_BYTES,
        },
    }
}


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


async fn purge_rows(client: &Client, scope: TenantScope, params: Vec<String>) -> Result<Vec<Vec<String>>, PgError> {
    let tenant = tenant_of(&scope).to_owned();
    let bound: Vec<&(dyn ToSql + Sync)> = std::iter::once(&tenant as &(dyn ToSql + Sync))
        .chain(params.iter().map(|param| param as &(dyn ToSql + Sync)))
        .collect();
    let (set_timeout, set_idle, purge) = purge_statements();
    let work = async {
        client.batch_execute(&format!("BEGIN; {set_timeout}; {set_idle}")).await.map_err(reduce)?;
        let outcome = client.query(&purge, &bound).await.map_err(reduce);
        let end = if outcome.is_ok() { "COMMIT" } else { "ROLLBACK" };
        client.batch_execute(end).await.map_err(reduce)?;
        outcome
    };
    let finished = tokio::time::timeout(Duration::from_millis(PURGE_CLIENT_DEADLINE_MILLIS), work).await;
    if finished.is_err() {
        if let Err(error) = client.batch_execute("ROLLBACK").await {
            tracing::warn!("rollback after a purge deadline failed: {error}");
        }
    }
    let rows = finished.map_err(|_elapsed| PgError::StatementTimeout {
        seconds: PURGE_CLIENT_DEADLINE_MILLIS / MILLIS_PER_SECOND,
    })??;
    rows.iter()
        .map(|row| (0..row.len()).map(|index| row.try_get::<_, String>(index).map_err(reduce)).collect())
        .collect()
}


fn alerts_executor<'a>(client: &'a Client) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    let plain = pg_executor(client, DEADLINE);
    move |scope, sql, params| -> RowFuture<'a> {
        if sql == PURGE_SQL {
            Box::pin(purge_rows(client, scope, params))
        } else {
            plain(scope, sql, params)
        }
    }
}


fn report(round: &Round) {
    let mut out = stdout();
    if writeln!(out, "round: {}", summary(round)).and_then(|()| out.flush()).is_err() {
        tracing::warn!("{WRITE_FAILED}");
    }
}


fn audit_purge(counts: &PurgedCounts) {
    let mut out = stdout();
    if writeln!(out, "audit: outbox purge {counts:?}").and_then(|()| out.flush()).is_err() {
        tracing::warn!("{WRITE_FAILED}");
    }
}


fn wait(duration: Duration) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


fn latest(source_file: &Path, fallback: &SourceSettings) -> SourceSettings {
    let read = std::fs::read_to_string(source_file)
        .map_err(|error| error.to_string())
        .and_then(|text| parse_source_settings(&text, &source_file.display().to_string(), wall_clock()).map_err(|error| error.to_string()));
    match read {
        Ok(settings) => settings,
        Err(reason) => {
            tracing::warn!("live settings unreadable, using the round snapshot: {reason}");
            fallback.clone()
        }
    }
}


async fn poll_loop(pg_file: &Path, source_file: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(pg_file)?, &pg_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, DEADLINE).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let holder = process_holder(
        Some(label),
        &std::env::var("HOSTNAME").unwrap_or_else(|_unset| "lab".to_owned()),
        std::process::id(),
        os_random,
    )?;
    let mut out = stdout();
    writeln!(out, "holder {holder}")?;
    out.flush()?;
    let alerts_exec = alerts_executor(&client);
    let mut exec = |scope: &TenantScope, statement: Statement| execute(&client, scope.clone(), statement);
    let audit = |counts: &PurgedCounts| audit_purge(counts);
    let hooks = RoundHooks {
        now: wall_clock,
        wait,
        report,
        audit_purge: &audit,
    };
    for _round in 0..MAX_ROUNDS {
        let source = parse_source_settings(&std::fs::read_to_string(source_file)?, &source_file.display().to_string(), wall_clock())?;
        let live = || latest(source_file, &source);
        run_rounds(1, &alerts_exec, &mut exec, &holder, &hooks, &live).await;
    }
    Ok(())
}


async fn seed(pg_file: &Path, tenant: &str, first: u64, count: u64) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(pg_file)?, &pg_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, DEADLINE).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let alerts_exec = pg_executor(&client, DEADLINE);
    let batch: Vec<SourceAlert> = (first..first + count).map(|index| source_alert(tenant, index)).collect();
    insert_alerts(&alerts_exec, &tenant_scope(tenant)?, &batch).await?;
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let outcome = match args.iter().map(String::as_str).collect::<Vec<&str>>().as_slice() {
        ["run", pg, source, label] => Some(runtime.block_on(poll_loop(Path::new(pg), Path::new(source), label))),
        ["seed", pg, tenant, first, count] => Some(runtime.block_on(async { seed(Path::new(pg), tenant, first.parse()?, count.parse()?).await })),
        _ => None,
    };
    match outcome {
        Some(Ok(())) => Ok(ExitCode::SUCCESS),
        Some(Err(error)) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
        None => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
