use crate::error::{reduce, PgError};
use crate::scope::{tenant_of, TenantScope};
use crate::types::SqlParameter;
use std::time::Duration;
use tokio::time::timeout;
use tokio_postgres::{Client, Row};


const MIN_TIMEOUT_MILLIS: u128 = 1;


/// A deadline under 1 ms is sent as 1 ms, because 0 disables the server limit. The `SET` goes in the same message as the script: the server enforces the deadline, and the client gives up at the same instant.
pub fn timed_script(sql: &str, deadline: Duration) -> String {
    format!("SET statement_timeout = {}; {sql}", deadline.as_millis().max(MIN_TIMEOUT_MILLIS))
}


pub async fn execute_script(client: &Client, sql: &str, deadline: Duration) -> Result<(), PgError> {
    timeout(deadline, client.batch_execute(&timed_script(sql, deadline)))
        .await
        .map_err(|_elapsed| PgError::StatementTimeout { seconds: deadline.as_secs() })?
        .map_err(reduce)
}


/// Sets the server-side deadline, then runs the statement: both share one client-side deadline.
pub async fn run_query(client: &Client, sql: &str, params: &[SqlParameter<'_>], deadline: Duration) -> Result<Vec<Row>, PgError> {
    let work = async {
        client.batch_execute(&timed_script("", deadline)).await.map_err(reduce)?;
        client.query(sql, params).await.map_err(reduce)
    };
    timeout(deadline, work)
        .await
        .map_err(|_elapsed| PgError::StatementTimeout { seconds: deadline.as_secs() })?
}


/// The statement text must use `$1` as the tenant filter; `params` start at `$2`.
pub async fn scoped_query(
    client: &Client,
    scope: &TenantScope,
    sql: &str,
    params: &[SqlParameter<'_>],
    deadline: Duration,
) -> Result<Vec<Row>, PgError> {
    let tenant = tenant_of(scope);
    let all: Vec<SqlParameter<'_>> = std::iter::once(&tenant as SqlParameter<'_>).chain(params.iter().copied()).collect();
    run_query(client, sql, &all, deadline).await
}


/// A query on a table without a `tenant` column, such as `schema_migrations`.
pub async fn global_query(client: &Client, sql: &str, deadline: Duration) -> Result<Vec<Row>, PgError> {
    run_query(client, sql, &[], deadline).await
}


pub fn column_text(row: &Row, index: usize) -> Result<String, PgError> {
    row.try_get(index).map_err(reduce)
}
