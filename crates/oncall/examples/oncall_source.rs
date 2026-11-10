use alerts::id::alert_id;
use alerts::model::{Alert as SourceAlert, Severity, Summary};
use alerts::pg::pg_executor;
use alerts::store::{insert_alerts, MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use chrono::{DateTime, Utc};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use oncall::alert::{Cell, Param, Statement};
use oncall::alert_source::{parse_source_settings, poll_all};
use oncall::error::StoreError;
use oncall::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use oncall::types::Row;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: oncall_source <pg.yaml> <tenant-a> <tenant-b>";


const DEADLINE: Duration = Duration::from_secs(30);


const SUMMARY_BYTES: u64 = 2;


const COLUMN_TITLE: usize = 2;


const COLUMN_HOST: usize = 3;


const ALERTS_PER_TENANT: u64 = 3;


const BASE_CREATED: u64 = 1_000;


const DUMP_SQL: &str = "SELECT a.fingerprint, d.severity, d.title, COALESCE(d.host, '') FROM oncall_alerts a JOIN oncall_alert_details d \
    ON d.tenant = a.tenant AND d.alert = a.id WHERE a.tenant = $1 ORDER BY a.id";


const SETTINGS_TEXT: &str =
    "tenants: [TENANT_A, TENANT_B]\nmax_per_poll: 2\ninterval_seconds: 30\nseverity_map:\n  informational: info\n  low: info\n  \
medium: ticket\n  high: page\n  critical: page-now\n";


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


async fn dump(client: &Client, scope: &TenantScope, out: &mut impl Write) -> Result<(), Box<dyn std::error::Error>> {
    let rows = scoped_query(client, scope, DUMP_SQL, &[], DEADLINE).await?;
    rows.iter().try_for_each(|row| {
        writeln!(
            out,
            "fingerprint={} severity={} title={} host={}",
            row.try_get::<_, String>(0)?,
            row.try_get::<_, String>(1)?,
            row.try_get::<_, String>(COLUMN_TITLE)?,
            row.try_get::<_, String>(COLUMN_HOST)?
        )?;
        Ok(())
    })
}


async fn scenario(settings_file: &Path, tenant_a: &str, tenant_b: &str) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, DEADLINE).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let mut out = stdout();
    let alerts_exec = pg_executor(&client, DEADLINE);
    let tenants = [tenant_a, tenant_b];
    for tenant in tenants {
        let scope = tenant_scope(tenant)?;
        let batch: Vec<SourceAlert> = (0..ALERTS_PER_TENANT).map(|index| source_alert(tenant, index)).collect();
        insert_alerts(&alerts_exec, &scope, &batch).await?;
    }
    let source_settings = parse_source_settings(&SETTINGS_TEXT.replace("TENANT_A", tenant_a).replace("TENANT_B", tenant_b), "inline")?;
    let mut exec = |scope: &TenantScope, statement: Statement| execute(&client, scope.clone(), statement);
    for round in 0..=ALERTS_PER_TENANT {
        let outcomes = poll_all(&alerts_exec, &mut exec, &source_settings, wall_clock).await;
        let summary: Vec<String> = outcomes
            .iter()
            .map(|(tenant, outcome)| {
                format!(
                    "{tenant}={}",
                    outcome.as_ref().map_or_else(|error| error.to_string(), ToString::to_string)
                )
            })
            .collect();
        writeln!(out, "poll {round}: {}", summary.join(" "))?;
    }
    for tenant in tenants {
        writeln!(out, "-- {tenant} on-call alerts")?;
        dump(&client, &tenant_scope(tenant)?, &mut out).await?;
    }
    Ok(())
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
