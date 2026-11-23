//! Lab proof of the attack path report store; the usage text below lists the commands.

use ad_posture::limits::Limits as SnapshotLimits;
use ad_posture::snapshot::read_snapshot;
use attack_paths::ad::graph_from_snapshot;
use attack_paths::model::{Graph, Limits, NodeKind, MAX_DEPTH, MAX_PATHS};
use attack_paths::paths::paths_to_critical;
use attack_paths::store::{get_report, list_reports, store_report_with_cap, MIGRATIONS, MIGRATION_NAMESPACE};
use attack_paths::types::RowFuture;
use core_config::load::load_file;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::query::{column_text, scoped_query};
use core_pg::scope::TenantScope;
use core_pg::settings::load_settings;
use core_pg::types::SqlParameter;
use std::fs::File;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_postgres::Client;


const USAGE: &str = "usage: attack_paths_store migrate <pg.yaml> | store <pg.yaml> <cap> <tenant> <snapshot.json|graph.yaml> <now> [max_paths] | list <pg.yaml> <tenant> <limit> | get <pg.yaml> <tenant> <id>";


const DEADLINE: Duration = Duration::from_secs(30);


const ARG_SETTINGS: usize = 2;


const ARG_CAP: usize = 3;


const ARG_TENANT: usize = 4;


const ARG_INPUT: usize = 5;


const ARG_NOW: usize = 6;


const ARG_MAX_PATHS: usize = 7;


const LIST_TENANT: usize = 3;


const LIST_LIMIT: usize = 4;


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


fn load_graph(path: &str) -> Result<Graph, String> {
    if path.ends_with(".json") {
        let snapshot = read_snapshot(File::open(path).map_err(failed)?, &SnapshotLimits::default()).map_err(failed)?;
        let mut built = graph_from_snapshot(&snapshot);
        built
            .graph
            .nodes
            .iter_mut()
            .for_each(|node| node.entry_point = matches!(node.kind, NodeKind::User | NodeKind::Workstation));
        Ok(built.graph)
    } else {
        load_file(Path::new(path)).map_err(failed)
    }
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
            let now = OffsetDateTime::parse(text(arguments, ARG_NOW)?, &Rfc3339).map_err(failed)?;
            let graph = load_graph(text(arguments, ARG_INPUT)?)?;
            let max_paths: usize = arguments
                .get(ARG_MAX_PATHS)
                .map_or(Ok(MAX_PATHS), |given| given.parse())
                .map_err(failed)?;
            let found = paths_to_critical(
                &graph,
                Limits {
                    max_depth: MAX_DEPTH,
                    max_paths,
                },
            )
            .map_err(failed)?;
            let outcome = store_report_with_cap(&exec, text(arguments, ARG_TENANT)?, &graph, &found, now, cap)
                .await
                .map_err(failed)?;
            writeln!(out, "{outcome:?}").map_err(failed)
        }
        "list" => {
            let limit: usize = text(arguments, LIST_LIMIT)?.parse().map_err(failed)?;
            let metas = list_reports(&exec, text(arguments, LIST_TENANT)?, limit).await.map_err(failed)?;
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
