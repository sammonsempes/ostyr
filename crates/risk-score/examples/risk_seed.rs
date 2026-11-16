//! Usage: risk_seed <module.yaml> <tenant> <alerts.tsv>. Migrates the alerts store and inserts one alert per line `rule<TAB>severity<TAB>age_seconds<TAB>host<TAB>user` through the alerts insert path (lab proof of T476).

use alerts::backend::{lease, unix_micros, MICROS_PER_SECOND};
use alerts::id::alert_id;
use alerts::model::{Alert, Severity, Summary};
use alerts::pg::pg_executor;
use alerts::settings::{open_pg_engine_from, ACTOR};
use alerts::store::{insert_alerts, MAX_ALERTS_PER_INSERT, MIGRATIONS, MIGRATION_NAMESPACE};
use core_api::server::new_listener;
use core_config::load::load_module;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::Semaphore;


const USAGE: &str = "usage: risk_seed <module.yaml> <tenant> <alerts.tsv>";


const TENANT_ARGUMENT: usize = 1;


const FILE_ARGUMENT: usize = 2;


const FIELDS: usize = 5;


const EVENT_TIME: &str = "2026-01-01T00:00:00Z";


const EMPTY_SUMMARY: &str = "{}";


fn severity_of(line_number: usize, name: &str) -> Result<Severity, Box<dyn Error>> {
    match name {
        "informational" => Ok(Severity::Informational),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(format!("line {line_number}: unknown severity {}", other.escape_debug()).into()),
    }
}


fn alert_of(tenant: &str, line_number: usize, line: &str, now_micros: u64) -> Result<Alert, Box<dyn Error>> {
    let fields: Vec<&str> = line.split('\t').collect();
    match fields.as_slice() {
        [rule, severity, age, host, user] => {
            let event_ids = vec![format!("event-{line_number}")];
            let named = |value: &str| (!value.is_empty()).then(|| value.to_owned());
            Ok(Alert {
                id: alert_id(tenant, rule, &event_ids),
                tenant: tenant.to_owned(),
                rule_id: (*rule).to_owned(),
                rule_title: (*rule).to_owned(),
                severity: severity_of(line_number, severity)?,
                event_time: EVENT_TIME.to_owned(),
                created_micros: now_micros.saturating_sub(age.parse::<u64>()?.saturating_mul(MICROS_PER_SECOND)),
                host_name: named(host),
                user_name: named(user),
                event_ids,
                summary: Summary {
                    text: EMPTY_SUMMARY.to_owned(),
                    truncated: false,
                    original_bytes: EMPTY_SUMMARY.len() as u64,
                },
            })
        }
        _ => Err(format!("line {line_number}: expected {FIELDS} tab-separated fields").into()),
    }
}


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let tenant = arguments.get(TENANT_ARGUMENT).ok_or(USAGE)?;
    let file = arguments.get(FILE_ARGUMENT).ok_or(USAGE)?;
    let scope = tenant_scope(tenant)?;
    let now_micros = unix_micros();
    let alerts = std::fs::read_to_string(file)?
        .lines()
        .enumerate()
        .map(|(index, line)| alert_of(tenant, index + 1, line, now_micros))
        .collect::<Result<Vec<Alert>, Box<dyn Error>>>()?;
    let loaded = load_module(Path::new(module_file))?;
    let (engine, _pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, new_listener(), ACTOR)?;
    let held = lease(&engine, &Arc::new(Semaphore::new(1))).await?;
    migrate(&held.client, MIGRATION_NAMESPACE, &MIGRATIONS, held.deadline).await?;
    let executor = pg_executor(&held.client, held.deadline);
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(&executor, &scope, batch).await?;
    }
    writeln!(stdout(), "inserted {inserted} of {} alerts for {tenant}", alerts.len())?;
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
