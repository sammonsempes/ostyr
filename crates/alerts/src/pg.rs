use crate::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::query::{column_text, scoped_query};
use core_pg::scope::TenantScope;
use core_pg::types::SqlParameter;
use std::time::Duration;
use tokio_postgres::Client;


/// `scoped_query` binds the tenant as `$1`, `params` start at `$2`, every column is read as text.
pub async fn pg_rows(client: &Client, deadline: Duration, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Row>, PgError> {
    let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
    let rows = scoped_query(client, &scope, sql, &bound, deadline).await?;
    rows.iter()
        .map(|row| (0..row.len()).map(|index| column_text(row, index)).collect())
        .collect()
}


/// The executor the store runs on against a real connection.
pub fn pg_executor<'a>(client: &'a Client, deadline: Duration) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(pg_rows(client, deadline, scope, sql, params)) }
}
