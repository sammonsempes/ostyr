use crate::api_model::SessionsBackend;
use crate::error::StoreError;
use crate::serve::{get_session, list_page};
use crate::store_model::{Cell, ListFilter, Page, Param, SessionRow, Statement};
use crate::types::Row;
use alerts::backend::lease;
use core_config::reload::ReloadEngine;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


pub const TYPE_INT8: &str = "int8";


pub const TYPE_BYTEA: &str = "bytea";


pub fn bound(params: &[Param]) -> Vec<Box<dyn ToSql + Send + Sync>> {
    params
        .iter()
        .map(|param| -> Box<dyn ToSql + Send + Sync> {
            match param {
                Param::Int(value) => Box::new(*value),
                Param::Text(value) => Box::new(value.clone()),
                Param::Bool(value) => Box::new(*value),
                Param::Bytes(value) => Box::new(value.clone()),
            }
        })
        .collect()
}


/// A value the driver cannot decode becomes `Cell::Unreadable`, which no decoder accepts: only its row is refused.
pub fn cell_of(row: &tokio_postgres::Row, index: usize, type_name: &str) -> Cell {
    let cell = match type_name {
        TYPE_INT8 => row.try_get::<_, Option<i64>>(index).map(|value| value.map_or(Cell::Null, Cell::Int)),
        TYPE_BYTEA => row
            .try_get::<_, Option<Vec<u8>>>(index)
            .map(|value| value.map_or(Cell::Null, Cell::Bytes)),
        _ => row.try_get::<_, Option<String>>(index).map(|value| value.map_or(Cell::Null, Cell::Text)),
    };
    cell.unwrap_or_else(|_unreadable| {
        tracing::debug!(index, "a stored value cannot be decoded");
        Cell::Unreadable
    })
}


/// The tenant is bound as `$1` by `scoped_query`, the statement parameters start at `$2`.
pub async fn pg_execute(client: &Client, deadline: Duration, scope: TenantScope, statement: Statement) -> Result<Vec<Row>, StoreError> {
    let boxed = bound(&statement.params);
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = scoped_query(client, &scope, statement.sql, &refs, deadline).await?;
    Ok(rows
        .iter()
        .map(|row| {
            row.columns()
                .iter()
                .enumerate()
                .map(|(index, column)| cell_of(row, index, column.type_().name()))
                .collect()
        })
        .collect())
}


/// One connection per request from the shared pool (a full pool is `Busy`); the permit goes back when the future ends or is dropped.
pub async fn pg_list(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    filter: ListFilter,
    after: Option<String>,
    limit: u32,
) -> Result<Page, StoreError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |bound_scope: &TenantScope, statement: Statement| pg_execute(&held.client, held.deadline, bound_scope.clone(), statement);
    list_page(&mut exec, &scope, &filter, after.as_deref(), limit).await
}


pub async fn pg_get(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    session_id: String,
) -> Result<Option<SessionRow>, StoreError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |bound_scope: &TenantScope, statement: Statement| pg_execute(&held.client, held.deadline, bound_scope.clone(), statement);
    get_session(&mut exec, &scope, &session_id).await
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> SessionsBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    SessionsBackend {
        list: Arc::new(move |scope, filter, after, limit| {
            Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, filter, after, limit))
        }),
        get: Arc::new(move |scope, session_id| Box::pin(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, session_id))),
    }
}
