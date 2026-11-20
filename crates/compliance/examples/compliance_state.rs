//! Lab proof. `compliance_state migrate <pg.yaml>`; `compliance_state run <pg.yaml> <tenant> <now> <cap> <baseline:control:asset:verdict>...`.

use alerts::types::RowFuture;
use compliance::alerting::report_run;
use compliance::model::Verdict;
use compliance::store::record_verdicts_with_cap;
use compliance::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use compliance::types::RunEntry;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::query::{column_text, scoped_query};
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::load_settings;
use core_pg::types::SqlParameter;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::Client;


const USAGE: &str = "usage: compliance_state migrate <pg.yaml> | run <pg.yaml> <tenant> <now> <cap> <baseline:control:asset:verdict>...";


const DEADLINE: Duration = Duration::from_secs(30);


const MIN_RUN_ARGS: usize = 6;


const ARG_SETTINGS: usize = 2;


const ARG_TENANT: usize = 3;


const ARG_NOW: usize = 4;


const ARG_CAP: usize = 5;


const ENTRY_PARTS: usize = 4;


fn verdict_of(name: &str) -> Option<Verdict> {
    match name {
        "pass" => Some(Verdict::Pass),
        "fail" => Some(Verdict::Fail {
            offending: Vec::new(),
            total: 1,
        }),
        "error" => Some(Verdict::Error { reason: "lab".to_owned() }),
        "excepted" => Some(Verdict::Excepted {
            owner: "lab".to_owned(),
            reason: "lab".to_owned(),
        }),
        _ => None,
    }
}


fn parse_entry(text: &str) -> Result<(String, String, String, Verdict), String> {
    let parts: Vec<&str> = text.splitn(ENTRY_PARTS, ':').collect();
    match parts.as_slice() {
        [baseline, control, asset, verdict] => verdict_of(verdict)
            .map(|found| ((*baseline).to_owned(), (*control).to_owned(), (*asset).to_owned(), found))
            .ok_or_else(|| format!("unknown verdict in `{text}`")),
        _ => Err(format!("bad entry `{text}`")),
    }
}


async fn pg_rows(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Vec<String>>, core_pg::error::PgError> {
    let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
    let rows = scoped_query(client, &scope, sql, &bound, DEADLINE).await?;
    rows.iter()
        .map(|row| (0..row.len()).map(|index| column_text(row, index)).collect())
        .collect()
}


async fn run_command(arguments: &[String]) -> Result<(), String> {
    let settings_path = arguments.get(ARG_SETTINGS).ok_or(USAGE)?;
    let settings = load_settings(Path::new(settings_path)).map_err(|error| error.to_string())?;
    let client = connect(&settings).await.map_err(|error| error.to_string())?;
    let mut out = stdout();
    if arguments.get(1).map(String::as_str) == Some("migrate") {
        let alerts_applied = migrate(&client, alerts::store::MIGRATION_NAMESPACE, &alerts::store::MIGRATIONS, DEADLINE)
            .await
            .map_err(|error| error.to_string())?;
        let applied = migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE)
            .await
            .map_err(|error| error.to_string())?;
        writeln!(out, "applied {alerts_applied:?} {applied:?}").map_err(|error| error.to_string())
    } else if arguments.len() >= MIN_RUN_ARGS {
        let scope = tenant_scope(arguments.get(ARG_TENANT).ok_or(USAGE)?).map_err(|error| error.to_string())?;
        let now: u64 = arguments.get(ARG_NOW).ok_or(USAGE)?.parse().map_err(|_error| USAGE.to_owned())?;
        let cap: i64 = arguments.get(ARG_CAP).ok_or(USAGE)?.parse().map_err(|_error| USAGE.to_owned())?;
        let parsed = arguments
            .get(MIN_RUN_ARGS..)
            .ok_or(USAGE)?
            .iter()
            .map(|text| parse_entry(text))
            .collect::<Result<Vec<_>, String>>()?;
        let run: Vec<RunEntry<'_>> = parsed
            .iter()
            .map(|(baseline, control, asset, verdict)| (baseline.as_str(), control.as_str(), asset.as_str(), verdict))
            .collect();
        let exec = |tenant: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(pg_rows(&client, tenant, sql, params)) };
        let outcome = record_verdicts_with_cap(&exec, &scope, &run, now, cap)
            .await
            .map_err(|error| error.to_string())?;
        report_run(&exec, &scope, &outcome, now, &mut out)
            .await
            .map_err(|error| error.to_string())
    } else {
        Err(USAGE.to_owned())
    }
}


#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    match run_command(&arguments).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let written = writeln!(stderr(), "{message}");
            if written.is_err() {
                tracing::error!("stderr is closed");
            }
            ExitCode::FAILURE
        }
    }
}
