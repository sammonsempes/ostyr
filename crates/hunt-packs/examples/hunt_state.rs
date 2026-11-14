use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::parse_settings;
use hunt_packs::store::{last_done, record_done, Param, MIGRATIONS, MIGRATION_NAMESPACE, STATEMENT_DEADLINE};
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: hunt_state <pg-settings.yaml> get|set <tenant> <pack-id> [<end>]";


const FIRST_COLUMN: usize = 0;


async fn execute(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<i64>, PgError> {
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
    let rows = scoped_query(client, &scope, sql, &refs, STATEMENT_DEADLINE).await?;
    rows.iter().map(|row| row.try_get(FIRST_COLUMN).map_err(reduce)).collect()
}


async fn scenario(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [settings_file, action, tenant, pack, rest @ ..] = args else {
        Err(USAGE)?
    };
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, settings_file)?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, STATEMENT_DEADLINE).await?;
    let mut exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| execute(&client, scope.clone(), sql, params);
    let text = match (action.as_str(), rest) {
        ("get", []) => format!("{:?}", last_done(&mut exec, tenant, pack).await?),
        ("set", [end]) => record_done(&mut exec, tenant, pack, end.parse()?).await?.to_string(),
        _ => Err(USAGE)?,
    };
    writeln!(stdout(), "{text}")?;
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
