use crate::error::PgError;
use crate::query::{reduce_statement, CLIENT_DEADLINE_MARGIN};
use std::time::Duration;
use tokio::time::timeout;
use tokio_postgres::Client;


pub const BEGIN_SQL: &str = "BEGIN";


pub const COMMIT_SQL: &str = "COMMIT";


pub const ROLLBACK_SQL: &str = "ROLLBACK";


/// One bare statement on the simple protocol, without a `SET` prefix so that it also runs in an aborted transaction; the client gives up a margin after the deadline.
pub async fn control(client: &Client, sql: &'static str, deadline: Duration) -> Result<(), PgError> {
    let cut = deadline.checked_add(CLIENT_DEADLINE_MARGIN).ok_or(PgError::DeadlineOverflow)?;
    timeout(cut, client.batch_execute(sql))
        .await
        .map_err(|_elapsed| PgError::ClientDeadline { seconds: deadline.as_secs() })?
        .map_err(|error| reduce_statement(error, deadline))
}


/// The isolation level is the one `connect` pins for the connection (READ COMMITTED); every statement until `commit` or `rollback` runs in the block.
pub async fn begin(client: &Client, deadline: Duration) -> Result<(), PgError> {
    control(client, BEGIN_SQL, deadline).await
}


pub async fn commit(client: &Client, deadline: Duration) -> Result<(), PgError> {
    control(client, COMMIT_SQL, deadline).await
}


pub async fn rollback(client: &Client, deadline: Duration) -> Result<(), PgError> {
    control(client, ROLLBACK_SQL, deadline).await
}


/// The three transaction boundaries, so a caller can inject one function for all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    Begin,
    Commit,
    Rollback,
}


pub async fn cross(client: &Client, boundary: Boundary, deadline: Duration) -> Result<(), PgError> {
    match boundary {
        Boundary::Begin => begin(client, deadline).await,
        Boundary::Commit => commit(client, deadline).await,
        Boundary::Rollback => rollback(client, deadline).await,
    }
}
