use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::parse_settings;
use hunt_packs::store::{
    last_done, list_findings, record_done, FindingRow, Param, MAX_FINDINGS_PAGE, MIGRATIONS, MIGRATION_NAMESPACE, STATEMENT_DEADLINE,
};
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Row};


const USAGE: &str = "usage: hunt_state <pg-settings.yaml> get|set <tenant> <pack-id> [<end>] | findings <tenant> [<since-end>[:<pack-id>]] [<limit>]";


const FIRST_COLUMN: usize = 0;


const SECOND_COLUMN: usize = 1;


const THIRD_COLUMN: usize = 2;


const FOURTH_COLUMN: usize = 3;


const FIFTH_COLUMN: usize = 4;


async fn query_rows(client: &Client, scope: &TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<Row>, PgError> {
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
    scoped_query(client, scope, sql, &refs, STATEMENT_DEADLINE).await
}


async fn execute(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<i64>, PgError> {
    let rows = query_rows(client, &scope, sql, params).await?;
    rows.iter().map(|row| row.try_get(FIRST_COLUMN).map_err(reduce)).collect()
}


fn finding_row(row: &Row) -> Result<FindingRow, PgError> {
    Ok(FindingRow {
        pack_id: row.try_get(FIRST_COLUMN).map_err(reduce)?,
        window_start: row.try_get(SECOND_COLUMN).map_err(reduce)?,
        window_end: row.try_get(THIRD_COLUMN).map_err(reduce)?,
        matches: row.try_get(FOURTH_COLUMN).map_err(reduce)?,
        max_matches: row.try_get(FIFTH_COLUMN).map_err(reduce)?,
    })
}


async fn execute_list(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<FindingRow>, PgError> {
    let rows = query_rows(client, &scope, sql, params).await?;
    rows.iter().map(finding_row).collect()
}


fn parse_cursor(text: Option<&String>) -> Result<(i64, String), Box<dyn std::error::Error>> {
    let (end, pack) = text.map_or(("0", ""), |value| value.split_once(':').unwrap_or((value.as_str(), "")));
    Ok((end.parse()?, pack.to_owned()))
}


async fn findings(client: &Client, tenant: &str, rest: &[String]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (cursor, limit) = match rest {
        [] => (None, None),
        [since] => (Some(since), None),
        [since, limit] => (Some(since), Some(limit)),
        _ => Err(USAGE)?,
    };
    let (since_end, since_pack) = parse_cursor(cursor)?;
    let limit_count: i64 = limit.map_or(Ok(MAX_FINDINGS_PAGE), |text| text.parse())?;
    let mut exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| execute_list(client, scope.clone(), sql, params);
    let page = list_findings(&mut exec, tenant, since_end, &since_pack, limit_count).await?;
    let lines: Vec<String> = page
        .rows
        .iter()
        .map(|row| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                row.window_end, row.pack_id, row.window_start, row.matches, row.max_matches
            )
        })
        .collect();
    Ok(lines)
}


async fn scenario(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [settings_file, action, tenant, rest @ ..] = args else { Err(USAGE)? };
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, settings_file)?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, STATEMENT_DEADLINE).await?;
    let mut exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| execute(&client, scope.clone(), sql, params);
    let lines = match (action.as_str(), rest) {
        ("get", [pack]) => vec![format!("{:?}", last_done(&mut exec, tenant, pack).await?)],
        ("set", [pack, end]) => vec![record_done(&mut exec, tenant, pack, end.parse()?).await?.to_string()],
        ("findings", _) => findings(&client, tenant, rest).await?,
        _ => Err(USAGE)?,
    };
    lines.iter().try_for_each(|line| writeln!(stdout(), "{line}"))?;
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
