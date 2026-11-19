use crate::error::StoreError;
use crate::store_model::{Cell, Param, Statement};
use crate::types::Row;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


/// The statement parameters as driver values, in order (`$2` onward: `execute` binds the tenant first).
pub fn bound(params: &[Param]) -> Vec<Box<dyn ToSql + Sync + Send>> {
    params
        .iter()
        .map(|param| -> Box<dyn ToSql + Sync + Send> {
            match param {
                Param::Int(value) => Box::new(*value),
                Param::Text(value) => Box::new(value.clone()),
                Param::Bool(value) => Box::new(*value),
                Param::Texts(value) => Box::new(value.clone()),
            }
        })
        .collect()
}


/// A `bigint` is an `Int` (NULL is `Null`), a `text` is a `Text`; any other column type, or a NULL text, refuses the row.
pub fn cell_of(row: &tokio_postgres::Row, index: usize) -> Result<Cell, StoreError> {
    let column = row.columns().get(index).ok_or(StoreError::BadRow { column: "cell" })?;
    let cell = match column.type_().name() {
        "int8" => row.try_get::<_, Option<i64>>(index).map(|value| value.map_or(Cell::Null, Cell::Int)),
        _ => row.try_get(index).map(Cell::Text),
    };
    cell.map_err(|_error| StoreError::BadRow { column: "cell" })
}


/// Runs one statement with the tenant of `scope` bound as `$1` and the parameters from `$2`, under `deadline`.
pub async fn execute(client: &Client, scope: TenantScope, statement: Statement, deadline: Duration) -> Result<Vec<Row>, StoreError> {
    let boxed = bound(&statement.params);
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = scoped_query(client, &scope, statement.sql, &refs, deadline).await?;
    rows.iter().map(|row| (0..row.len()).map(|index| cell_of(row, index)).collect()).collect()
}
