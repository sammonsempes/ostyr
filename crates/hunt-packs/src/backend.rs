use crate::api::{permit_backend, read_findings};
use crate::api_model::{FindingsQuery, FindingsReply};
use crate::error::FindingsError;
use crate::store::{FindingRow, Param, StateError, STATEMENT_DEADLINE};
use crate::types::FindingsFn;
use core_config::reload::{current_config, ReloadEngine};
use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Row};


pub const ACTOR: &str = "hunts";


const FIRST_COLUMN: usize = 0;


const SECOND_COLUMN: usize = 1;


const THIRD_COLUMN: usize = 2;


const FOURTH_COLUMN: usize = 3;


const FIFTH_COLUMN: usize = 4;


/// Runs one statement with the tenant bound as `$1` and the given parameters from `$2`.
pub async fn query_rows(client: &Client, scope: &TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<Row>, PgError> {
    let boxed: Vec<Box<dyn ToSql + Sync + Send>> = params
        .into_iter()
        .map(|param| -> Box<dyn ToSql + Sync + Send> {
            match param {
                Param::Text(text) => Box::new(text),
                Param::Int(number) => Box::new(number),
            }
        })
        .collect();
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    scoped_query(client, scope, sql, &refs, STATEMENT_DEADLINE).await
}


/// The first column of every row as an int8.
pub async fn execute(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<i64>, PgError> {
    let rows = query_rows(client, &scope, sql, params).await?;
    rows.iter().map(|row| row.try_get(FIRST_COLUMN).map_err(reduce)).collect()
}


pub fn finding_row(row: &Row) -> Result<FindingRow, PgError> {
    Ok(FindingRow {
        pack_id: row.try_get(FIRST_COLUMN).map_err(reduce)?,
        window_start: row.try_get(SECOND_COLUMN).map_err(reduce)?,
        window_end: row.try_get(THIRD_COLUMN).map_err(reduce)?,
        matches: row.try_get(FOURTH_COLUMN).map_err(reduce)?,
        max_matches: row.try_get(FIFTH_COLUMN).map_err(reduce)?,
    })
}


pub async fn execute_list(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<FindingRow>, PgError> {
    let rows = query_rows(client, &scope, sql, params).await?;
    rows.iter().map(finding_row).collect()
}


/// One connection per read, opened with the settings current at that moment.
pub async fn read_pg(engine: Arc<ReloadEngine<PgSettings>>, scope: TenantScope, query: FindingsQuery) -> Result<FindingsReply, FindingsError> {
    let settings = current_config(&engine);
    let client = connect(&settings).await.map_err(StateError::from)?;
    let mut list_exec = |bound: &TenantScope, sql: &'static str, params: Vec<Param>| execute_list(&client, bound.clone(), sql, params);
    let mut count_exec = |bound: &TenantScope, sql: &'static str, params: Vec<Param>| execute(&client, bound.clone(), sql, params);
    read_findings(&mut list_exec, &mut count_exec, &scope, &query).await
}


/// One permit of the shared semaphore for the whole read, else 429 before any connection.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> FindingsFn {
    let reading: FindingsFn = Arc::new(move |scope, query| Box::pin(read_pg(Arc::clone(&engine), scope, query)));
    permit_backend(permits, reading)
}
