use crate::error::{reduce, PgError};
use crate::scope::{tenant_of, TenantScope};
use crate::types::SqlParameter;
use std::time::Duration;
use tokio::time::timeout;
use tokio_postgres::{Client, Row};


const MIN_TIMEOUT_MILLIS: u128 = 1;


pub const CLIENT_DEADLINE_MARGIN: Duration = Duration::from_secs(5);


pub const QUERY_WINDOWS: u32 = 2;


pub const STATEMENT_TIMEOUT_SQLSTATE: &str = "57014";


/// A deadline under 1 ms is sent as 1 ms, because 0 disables the server limit.
pub fn timeout_millis(deadline: Duration) -> u128 {
    deadline.as_millis().max(MIN_TIMEOUT_MILLIS)
}


/// The `SET` goes in the same message as the script: the server enforces the deadline, and the client gives up at the same instant.
pub fn timed_script(sql: &str, deadline: Duration) -> String {
    format!("SET statement_timeout = {}; {sql}", timeout_millis(deadline))
}


/// The server's own cancel (SQLSTATE 57014) is the only source of `StatementTimeout`.
pub fn reduce_statement(error: tokio_postgres::Error, deadline: Duration) -> PgError {
    match reduce(error) {
        PgError::Server { code, .. } if code == STATEMENT_TIMEOUT_SQLSTATE => PgError::StatementTimeout { seconds: deadline.as_secs() },
        other => other,
    }
}


/// The client gives up `CLIENT_DEADLINE_MARGIN` after the server limit, so a statement that committed inside the margin is reported done.
pub async fn execute_script(client: &Client, sql: &str, deadline: Duration) -> Result<(), PgError> {
    let cut = deadline.checked_add(CLIENT_DEADLINE_MARGIN).ok_or(PgError::DeadlineOverflow)?;
    timeout(cut, client.batch_execute(&timed_script(sql, deadline)))
        .await
        .map_err(|_elapsed| PgError::ClientDeadline { seconds: deadline.as_secs() })?
        .map_err(|error| reduce_statement(error, deadline))
}


/// The extended protocol restarts the server limit per message (Parse, then Execute): the client waits two windows plus the margin.
pub async fn run_query(client: &Client, sql: &str, params: &[SqlParameter<'_>], deadline: Duration) -> Result<Vec<Row>, PgError> {
    let work = async {
        client
            .batch_execute(&timed_script("", deadline))
            .await
            .map_err(|error| reduce_statement(error, deadline))?;
        client.query(sql, params).await.map_err(|error| reduce_statement(error, deadline))
    };
    let cut = deadline
        .checked_mul(QUERY_WINDOWS)
        .and_then(|windows| windows.checked_add(CLIENT_DEADLINE_MARGIN))
        .ok_or(PgError::DeadlineOverflow)?;
    timeout(cut, work)
        .await
        .map_err(|_elapsed| PgError::ClientDeadline { seconds: deadline.as_secs() })?
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
