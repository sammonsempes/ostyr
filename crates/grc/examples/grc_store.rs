//! Lab proof of the report store; the usage text below lists the commands.

use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::query::{column_text, scoped_query};
use core_pg::scope::TenantScope;
use core_pg::settings::load_settings;
use core_pg::types::SqlParameter;
use grc::builtin::resolve_framework;
use grc::evaluate::evaluate_framework;
use grc::inputs::{load_indicators, load_manual};
use grc::report::build_report;
use grc::risk::Register;
use grc::store::{get_report, list_reports, store_report_with_cap, MIGRATIONS, MIGRATION_NAMESPACE};
use grc::types::RowFuture;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_postgres::Client;


const USAGE: &str = "usage: grc_store migrate <pg.yaml> | store <pg.yaml> <cap> <framework> <indicators> <manual> <tenant> <now> | list <pg.yaml> <tenant> <limit> [framework] | get <pg.yaml> <tenant> <id>";


const DEADLINE: Duration = Duration::from_secs(30);


const ARG_SETTINGS: usize = 2;


const ARG_CAP: usize = 3;


const ARG_FRAMEWORK: usize = 4;


const ARG_INDICATORS: usize = 5;


const ARG_MANUAL: usize = 6;


const ARG_TENANT: usize = 7;


const ARG_NOW: usize = 8;


const LIST_TENANT: usize = 3;


const LIST_LIMIT: usize = 4;


const LIST_FRAMEWORK: usize = 5;


const GET_TENANT: usize = 3;


const GET_ID: usize = 4;


fn text(arguments: &[String], index: usize) -> Result<&str, String> {
    arguments.get(index).map(String::as_str).ok_or_else(|| USAGE.to_owned())
}


async fn pg_rows(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Vec<String>>, core_pg::error::PgError> {
    let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
    let rows = scoped_query(client, &scope, sql, &bound, DEADLINE).await?;
    rows.iter()
        .map(|row| (0..row.len()).map(|index| column_text(row, index)).collect())
        .collect()
}


fn failed<Cause: std::fmt::Display>(error: Cause) -> String {
    error.to_string()
}


async fn run_command(arguments: &[String]) -> Result<(), String> {
    let settings = load_settings(Path::new(text(arguments, ARG_SETTINGS)?)).map_err(failed)?;
    let client = connect(&settings).await.map_err(failed)?;
    let exec = |tenant: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(pg_rows(&client, tenant, sql, params)) };
    let mut out = stdout();
    match text(arguments, 1)? {
        "migrate" => {
            let applied = migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await.map_err(failed)?;
            writeln!(out, "applied {applied:?}").map_err(failed)
        }
        "store" => {
            let cap: i64 = text(arguments, ARG_CAP)?.parse().map_err(failed)?;
            let tenant = text(arguments, ARG_TENANT)?;
            let framework = resolve_framework(text(arguments, ARG_FRAMEWORK)?).map_err(failed)?;
            let indicators = load_indicators(Path::new(text(arguments, ARG_INDICATORS)?)).map_err(failed)?;
            let manual = load_manual(Path::new(text(arguments, ARG_MANUAL)?)).map_err(failed)?;
            let now = OffsetDateTime::parse(text(arguments, ARG_NOW)?, &Rfc3339).map_err(failed)?;
            let evaluated = evaluate_framework(tenant, &framework, &indicators, &manual, now).map_err(failed)?;
            let register = Register {
                tenant: tenant.to_owned(),
                risks: Vec::new(),
                actions: Vec::new(),
            };
            let compliance = build_report(&framework, &evaluated, &register, now.date()).map_err(failed)?;
            let outcome = store_report_with_cap(&exec, tenant, &compliance, cap).await.map_err(failed)?;
            writeln!(out, "{outcome:?}").map_err(failed)
        }
        "list" => {
            let limit: usize = text(arguments, LIST_LIMIT)?.parse().map_err(failed)?;
            let framework = arguments.get(LIST_FRAMEWORK).map(String::as_str);
            let metas = list_reports(&exec, text(arguments, LIST_TENANT)?, framework, limit)
                .await
                .map_err(failed)?;
            metas.iter().try_for_each(|meta| writeln!(out, "{meta:?}")).map_err(failed)
        }
        "get" => {
            let id: i64 = text(arguments, GET_ID)?.parse().map_err(failed)?;
            let found = get_report(&exec, text(arguments, GET_TENANT)?, id).await.map_err(failed)?;
            match found {
                Some(stored) => writeln!(out, "{}", stored.body).map_err(failed),
                None => writeln!(out, "not found").map_err(failed),
            }
        }
        _ => Err(USAGE.to_owned()),
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
