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
use oncall::alert_source::{parse_source_settings, poll_all, Round, SourceSettings, LEASE_SQL};
use oncall::error::StoreError;
use oncall::holder::process_holder;
use oncall::link::os_random;
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


const BACKLOG_ALERTS: u64 = 2;


const CLOCK_MARGIN: Duration = Duration::from_secs(2);


const POLLER: &str = "poller-a";


const OTHER_POLLER: &str = "poller-b";


const FRESH_ALERTS: u64 = 1;


const STEAL_ON_LEASE_CALL: usize = 2;


const LEASE_DUMP_SQL: &str = "SELECT holder, (expires_at > now())::text FROM oncall_poller_lease";


const STEAL_SQL: &str = "UPDATE oncall_poller_lease SET holder = 'poller-thief', expires_at = now() + interval '1 hour'";


const EXPIRE_SQL: &str = "UPDATE oncall_poller_lease SET expires_at = now() - interval '1 second'";


const PID_NAME: u32 = 1;


const GHOST_OFFSET: u64 = ALERTS_PER_TENANT + 50;


const FRESH_OFFSET: u64 = ALERTS_PER_TENANT + 10;


const GHOST_COUNT_SQL: &str = "SELECT count(*)::text FROM alert_outbox WHERE tenant = $1";


const BASE_CREATED: u64 = 1_000;


const DUMP_SQL: &str = "SELECT a.fingerprint, d.severity, d.title, COALESCE(d.host, '') FROM oncall_alerts a JOIN oncall_alert_details d \
    ON d.tenant = a.tenant AND d.alert = a.id WHERE a.tenant = $1 ORDER BY a.id";


const SETTINGS_TEXT: &str =
    "tenants: [TENANT_A, TENANT_B]\nmax_per_poll: 2\ninterval_seconds: 30\nseverity_map:\n  informational: info\n  low: info\n  \
medium: ticket\n  high: page\n  critical: page-now\n";


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


async fn lease_line(client: &Client) -> Result<String, Box<dyn std::error::Error>> {
    let row = client.query_one(LEASE_DUMP_SQL, &[]).await?;
    Ok(format!(
        "lease holder={} unexpired={}",
        row.try_get::<_, String>(0)?,
        row.try_get::<_, String>(1)?
    ))
}


async fn t236_proofs(
    client: &Client,
    alerts_exec: alerts::types::Executor<'_, '_>,
    settings: &SourceSettings,
    tenants: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = process_holder(Some("poller-b"), "lab", PID_NAME, os_random)?;
    let second = process_holder(Some("poller-b"), "lab", PID_NAME, os_random)?;
    writeln!(out, "same label, ids: {first} {second} differ={}", first != second)?;
    client.execute(EXPIRE_SQL, &[]).await?;
    let mut exec = |scope: &TenantScope, statement: Statement| execute(client, scope.clone(), statement);
    writeln!(
        out,
        "first poller: {}",
        summary(&poll_all(alerts_exec, &mut exec, settings, &first, wall_clock).await)
    )?;
    writeln!(
        out,
        "same label again: {}",
        summary(&poll_all(alerts_exec, &mut exec, settings, &second, wall_clock).await)
    )?;
    writeln!(out, "{}", lease_line(client).await?)?;
    let ghost = format!("{}-ghost", tenants.first().ok_or("no tenant")?);
    insert_alerts(alerts_exec, &tenant_scope(&ghost)?, &[source_alert(&ghost, GHOST_OFFSET)]).await?;
    for tenant in tenants {
        insert_alerts(alerts_exec, &tenant_scope(tenant)?, &[source_alert(tenant, FRESH_OFFSET)]).await?;
    }
    let mut lease_calls: usize = 0;
    let mut stealing = |scope: &TenantScope, statement: Statement| {
        lease_calls += usize::from(statement.sql == LEASE_SQL);
        let steal = statement.sql == LEASE_SQL && lease_calls == STEAL_ON_LEASE_CALL;
        let owned_scope = scope.clone();
        async move {
            if steal {
                client
                    .execute(STEAL_SQL, &[])
                    .await
                    .map_err(|_error| StoreError::BadRow { column: "steal" })?;
            }
            execute(client, owned_scope, statement).await
        }
    };
    writeln!(
        out,
        "lease taken mid-round: {}",
        summary(&poll_all(alerts_exec, &mut stealing, settings, &first, wall_clock).await)
    )?;
    writeln!(out, "{}", lease_line(client).await?)?;
    let left = client.query_one(GHOST_COUNT_SQL, &[&ghost]).await?;
    writeln!(out, "ghost outbox rows after the stolen round: {}", left.try_get::<_, String>(0)?)?;
    client.execute(EXPIRE_SQL, &[]).await?;
    writeln!(
        out,
        "next holder purges: {}",
        summary(&poll_all(alerts_exec, &mut exec, settings, &second, wall_clock).await)
    )?;
    Ok(())
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
    let source_settings = parse_source_settings(
        &SETTINGS_TEXT.replace("TENANT_A", tenant_a).replace("TENANT_B", tenant_b),
        "inline",
        wall_clock(),
    )?;
    let mut exec = |scope: &TenantScope, statement: Statement| execute(&client, scope.clone(), statement);
    for round_number in 0..=ALERTS_PER_TENANT {
        let round = poll_all(&alerts_exec, &mut exec, &source_settings, POLLER, wall_clock).await;
        writeln!(out, "poll {round_number}: {}", summary(&round))?;
    }
    for tenant in tenants {
        let scope = tenant_scope(tenant)?;
        let mut late = source_alert(tenant, ALERTS_PER_TENANT);
        late.created_micros = 1;
        insert_alerts(&alerts_exec, &scope, &[late]).await?;
    }
    let late = poll_all(&alerts_exec, &mut exec, &source_settings, POLLER, wall_clock).await;
    writeln!(out, "late poll: {}", summary(&late))?;
    let ghost = format!("{tenant_a}-ghost");
    let ghost_scope = tenant_scope(&ghost)?;
    let ghost_batch: Vec<SourceAlert> = (0..ALERTS_PER_TENANT).map(|index| source_alert(&ghost, index)).collect();
    insert_alerts(&alerts_exec, &ghost_scope, &ghost_batch).await?;
    let backlog: Vec<SourceAlert> = (ALERTS_PER_TENANT + 1..ALERTS_PER_TENANT + 1 + BACKLOG_ALERTS)
        .map(|index| source_alert(tenant_b, index))
        .collect();
    insert_alerts(&alerts_exec, &tenant_scope(tenant_b)?, &backlog).await?;
    tokio::time::sleep(CLOCK_MARGIN).await;
    let added = wall_clock().to_rfc3339();
    tokio::time::sleep(CLOCK_MARGIN).await;
    let fresh: Vec<SourceAlert> = (ALERTS_PER_TENANT + 1 + BACKLOG_ALERTS..ALERTS_PER_TENANT + 1 + BACKLOG_ALERTS + FRESH_ALERTS)
        .map(|index| source_alert(tenant_b, index))
        .collect();
    insert_alerts(&alerts_exec, &tenant_scope(tenant_b)?, &fresh).await?;
    let dated = format!(
        "{}added_at:\n  {tenant_b}: {added}\n",
        SETTINGS_TEXT.replace("TENANT_A", tenant_a).replace("TENANT_B", tenant_b)
    );
    let dated_settings = parse_source_settings(&dated, "inline", wall_clock())?;
    writeln!(
        out,
        "added tenant {tenant_b} later: {}",
        summary(&poll_all(&alerts_exec, &mut exec, &dated_settings, POLLER, wall_clock).await)
    )?;
    writeln!(
        out,
        "other poller: {}",
        summary(&poll_all(&alerts_exec, &mut exec, &dated_settings, OTHER_POLLER, wall_clock).await)
    )?;
    writeln!(
        out,
        "second round: {}",
        summary(&poll_all(&alerts_exec, &mut exec, &dated_settings, POLLER, wall_clock).await)
    )?;
    t236_proofs(&client, &alerts_exec, &dated_settings, &tenants, &mut out).await?;
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
