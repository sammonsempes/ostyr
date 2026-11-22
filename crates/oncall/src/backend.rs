use crate::alert::{Alert, AlertPage, Cell, Event, Param, Statement};
use crate::api_model::OncallBackend;
use crate::error::{ReadError, StoreError};
use crate::store::{apply_event, get_alert, open_alert_page};
use crate::types::Row;
use alerts::backend::lease;
use chrono::{DateTime, Utc};
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


pub const TYPE_TIMESTAMPTZ: &str = "timestamptz";


pub const TYPE_BOOL: &str = "bool";


pub fn bound(statement: &Statement) -> Vec<Box<dyn ToSql + Send + Sync>> {
    statement
        .params
        .iter()
        .map(|param| -> Box<dyn ToSql + Send + Sync> {
            match param {
                Param::Int(value) => Box::new(*value),
                Param::Text(value) => Box::new(value.clone()),
                Param::OptText(value) => Box::new(value.clone()),
                Param::Time(value) => Box::new(*value),
            }
        })
        .collect()
}


/// A value the driver cannot decode becomes `Cell::Unreadable`, which no decoder accepts: only its row is refused.
pub fn cell_of(row: &tokio_postgres::Row, index: usize, type_name: &str) -> Cell {
    let cell = match type_name {
        TYPE_BOOL => row.try_get(index).map(Cell::Bool),
        TYPE_INT8 => row.try_get(index).map(Cell::Int),
        TYPE_TIMESTAMPTZ => row.try_get::<_, Option<DateTime<Utc>>>(index).map(Cell::Time),
        _ => row.try_get(index).map(Cell::Text),
    };
    cell.unwrap_or_else(|_unreadable| {
        tracing::debug!(index, "a stored value cannot be decoded");
        Cell::Unreadable
    })
}


/// The tenant is bound as `$1` by `scoped_query`, the statement parameters start at `$2`.
pub async fn execute(client: &Client, deadline: Duration, scope: TenantScope, statement: Statement) -> Result<Vec<Row>, StoreError> {
    let boxed = bound(&statement);
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
pub async fn pg_list(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>, scope: TenantScope, limit: u32) -> Result<AlertPage, ReadError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |bound_scope: &TenantScope, statement: Statement| execute(&held.client, held.deadline, bound_scope.clone(), statement);
    Ok(open_alert_page(&mut exec, &scope, limit).await?)
}


/// An alert of another tenant and an unknown id are the same `None`: one statement with the tenant as `$1`.
pub async fn pg_get(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>, scope: TenantScope, id: i64) -> Result<Option<Alert>, ReadError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |bound_scope: &TenantScope, statement: Statement| execute(&held.client, held.deadline, bound_scope.clone(), statement);
    match get_alert(&mut exec, &scope, id).await {
        Ok(alert) => Ok(Some(alert)),
        Err(StoreError::NotFound) => Ok(None),
        Err(other) => Err(other.into()),
    }
}


/// Reads, transitions and writes under the tenant bound as `$1` on both statements; a moved version or a refused transition is a `StoreError`.
pub async fn pg_apply(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    id: i64,
    event: Event,
    now: DateTime<Utc>,
) -> Result<Alert, ReadError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |bound_scope: &TenantScope, statement: Statement| execute(&held.client, held.deadline, bound_scope.clone(), statement);
    Ok(apply_event(&mut exec, &scope, id, event, now).await?)
}


pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> OncallBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    let get_engine = Arc::clone(&engine);
    let get_permits = Arc::clone(&permits);
    OncallBackend {
        list: Arc::new(move |scope, limit| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, limit))),
        get: Arc::new(move |scope, id| Box::pin(pg_get(Arc::clone(&get_engine), Arc::clone(&get_permits), scope, id))),
        apply: Arc::new(move |scope, id, event, now| Box::pin(pg_apply(Arc::clone(&engine), Arc::clone(&permits), scope, id, event, now))),
        clock: Utc::now,
    }
}
