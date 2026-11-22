//! Lab tool. `cases_indicators <pg.yaml> <tenant> <now seconds|now>` prints the GRC indicator file (a JSON array) on stdout.

use alerts::types::RowFuture;
use cases::indicator::{incident_indicator, indicator_json, warning_line};
use core_pg::connect::connect;
use core_pg::query::{column_text, scoped_query};
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::load_settings;
use core_pg::types::SqlParameter;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_postgres::Client;


const USAGE: &str = "usage: cases_indicators <pg.yaml> <tenant> <now seconds|now>";


const DEADLINE: Duration = Duration::from_secs(30);


const ARG_SETTINGS: usize = 1;


const ARG_TENANT: usize = 2;


const ARG_NOW: usize = 3;


const NOW_WORD: &str = "now";


async fn pg_rows(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Vec<String>>, core_pg::error::PgError> {
    let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
    let rows = scoped_query(client, &scope, sql, &bound, DEADLINE).await?;
    rows.iter()
        .map(|row| (0..row.len()).map(|index| column_text(row, index)).collect())
        .collect()
}


fn now_of(text: &str) -> Result<i64, String> {
    if text == NOW_WORD {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())
            .and_then(|elapsed| i64::try_from(elapsed.as_secs()).map_err(|error| error.to_string()))
    } else {
        text.parse().map_err(|_error| USAGE.to_owned())
    }
}


async fn run_command(arguments: &[String]) -> Result<(), String> {
    let settings = load_settings(Path::new(arguments.get(ARG_SETTINGS).ok_or(USAGE)?)).map_err(|error| error.to_string())?;
    let scope = tenant_scope(arguments.get(ARG_TENANT).ok_or(USAGE)?).map_err(|error| error.to_string())?;
    let now = now_of(arguments.get(ARG_NOW).ok_or(USAGE)?)?;
    let client = connect(&settings).await.map_err(|error| error.to_string())?;
    let exec = |tenant: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(pg_rows(&client, tenant, sql, params)) };
    let outcome = incident_indicator(&exec, &scope, now).await.map_err(|error| error.to_string())?;
    let rows: Vec<_> = outcome.row.iter().cloned().collect();
    let text = indicator_json(&rows).map_err(|error| error.to_string())?;
    writeln!(stdout(), "{text}").map_err(|error| error.to_string())?;
    if rows.is_empty() {
        writeln!(stderr(), "{}", warning_line(&outcome.counts)).map_err(|error| error.to_string())
    } else {
        Ok(())
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
