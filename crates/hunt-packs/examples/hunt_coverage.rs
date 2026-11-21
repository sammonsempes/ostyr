use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::parse_settings;
use hunt_packs::coverage::{check_period, read_coverage, FindingsRow, RunRow};
use hunt_packs::model::HuntPack;
use hunt_packs::packs::load_packs;
use hunt_packs::store::{Param, STATEMENT_DEADLINE};
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Row};


const USAGE: &str = "usage: hunt_coverage <pg-settings.yaml> <packs-dir> <tenant> <from> <to> [<deadline-milliseconds> [<hand-built-pack-id>]]";


const MAX_OPTIONAL: usize = 2;


const KIND_COLUMN: usize = 0;


const ID_COLUMN: usize = 1;


const VALUE_COLUMN: usize = 2;


const MATCHES_COLUMN: usize = 3;


const SATURATED_COLUMN: usize = 4;


const NEGATIVE_COLUMN: usize = 5;


async fn query_rows(client: &Client, scope: &TenantScope, sql: &'static str, params: Vec<Param>, deadline: Duration) -> Result<Vec<Row>, PgError> {
    let boxed: Vec<Box<dyn ToSql + Sync>> = params
        .into_iter()
        .map(|param| -> Box<dyn ToSql + Sync> {
            match param {
                Param::Text(text) => Box::new(text),
                Param::Int(number) => Box::new(number),
            }
        })
        .collect();
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    scoped_query(client, scope, sql, &refs, deadline).await
}


fn run_row(row: &Row) -> Result<RunRow, PgError> {
    Ok(RunRow {
        kind: row.try_get(KIND_COLUMN).map_err(reduce)?,
        pack_id: row.try_get(ID_COLUMN).map_err(reduce)?,
        value: row.try_get(VALUE_COLUMN).map_err(reduce)?,
    })
}


fn findings_row(row: &Row) -> Result<FindingsRow, PgError> {
    Ok(FindingsRow {
        kind: row.try_get(KIND_COLUMN).map_err(reduce)?,
        pack_id: row.try_get(ID_COLUMN).map_err(reduce)?,
        windows: row.try_get(VALUE_COLUMN).map_err(reduce)?,
        matches: row.try_get(MATCHES_COLUMN).map_err(reduce)?,
        saturated: row.try_get(SATURATED_COLUMN).map_err(reduce)?,
        negative: row.try_get(NEGATIVE_COLUMN).map_err(reduce)?,
    })
}


async fn scenario(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [settings_file, dir, tenant, from, to, rest @ ..] = args else {
        Err(USAGE)?
    };
    (rest.len() <= MAX_OPTIONAL).then_some(()).ok_or(USAGE)?;
    let deadline = rest
        .first()
        .map(|text| text.parse().map(Duration::from_millis))
        .transpose()?
        .unwrap_or(STATEMENT_DEADLINE);
    let period = check_period(from.parse()?, to.parse()?)?;
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, settings_file)?;
    let mut packs: Vec<_> = load_packs(Path::new(dir))?.into_iter().map(|loaded| loaded.pack).collect();
    let hand_built = rest.get(1).zip(packs.first()).map(|(id, first)| HuntPack {
        id: id.clone(),
        ..first.clone()
    });
    packs.extend(hand_built);
    let client = connect(&settings).await?;
    let mut runs_exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| {
        let client_ref = &client;
        let bound = scope.clone();
        async move {
            query_rows(client_ref, &bound, sql, params, deadline)
                .await?
                .iter()
                .map(run_row)
                .collect::<Result<Vec<_>, _>>()
        }
    };
    let mut findings_exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| {
        let client_ref = &client;
        let bound = scope.clone();
        async move {
            query_rows(client_ref, &bound, sql, params, deadline)
                .await?
                .iter()
                .map(findings_row)
                .collect::<Result<Vec<_>, _>>()
        }
    };
    let report = read_coverage(&mut runs_exec, &mut findings_exec, tenant, &packs, &period).await?;
    writeln!(stdout(), "{}", serde_json::to_string_pretty(&report)?)?;
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    match runtime.block_on(scenario(&args)) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
