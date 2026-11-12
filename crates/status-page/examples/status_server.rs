//! Usage: `status_server <server.yaml> <listen-address>`; the settings file named in it is reloaded on change, and with `pg_file` the page comes from the store.
use core_pg::connect::connect;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::load_settings;
use status_page::app::{run_app_with, AppFile};
use status_page::error::StoreError;
use status_page::store::{read_published, MAX_PUBLISHED};
use status_page::store_model::{Cell, Param, PublishedRead, Statement};
use status_page::types::{IncidentReadFn, Row};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: status_server <server.yaml> <listen-address>";


fn bound(params: &[Param]) -> Vec<Box<dyn ToSql + Sync + Send>> {
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


fn cell_of(row: &tokio_postgres::Row, index: usize) -> Result<Cell, StoreError> {
    let column = row.columns().get(index).ok_or(StoreError::BadRow { column: "cell" })?;
    let cell = match column.type_().name() {
        "int8" => row.try_get::<_, Option<i64>>(index).map(|value| value.map_or(Cell::Null, Cell::Int)),
        _ => row.try_get(index).map(Cell::Text),
    };
    cell.map_err(|_error| StoreError::BadRow { column: "cell" })
}


async fn execute(client: &Client, scope: TenantScope, statement: Statement, deadline: Duration) -> Result<Vec<Row>, StoreError> {
    let boxed = bound(&statement.params);
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = scoped_query(client, &scope, statement.sql, &refs, deadline).await?;
    rows.iter().map(|row| (0..row.len()).map(|index| cell_of(row, index)).collect()).collect()
}


/// One read: the core-pg settings are loaded afresh, one connection is opened (connect timeout) and queried under the statement timeout.
async fn read_once(pg_file: &Path, scope: &TenantScope, services: &[String]) -> Result<PublishedRead, StoreError> {
    let settings = load_settings(pg_file)?;
    let deadline = Duration::from_secs(settings.statement_timeout_secs);
    let client = connect(&settings).await?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&client, query_scope.clone(), statement, deadline);
    read_published(&mut exec, scope, services, MAX_PUBLISHED).await
}


fn pg_reader(pg_file: PathBuf) -> IncidentReadFn {
    Box::new(move |scope, services| {
        let path = pg_file.clone();
        Box::pin(async move { read_once(&path, &scope, &services).await })
    })
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(USAGE)?;
    let address = args.next().ok_or(USAGE)?;
    let file: AppFile = core_config::load::load_file(Path::new(&path))?;
    let reader = file.pg_file.clone().map(pg_reader);
    let listener = TcpListener::bind(address).await?;
    let shutdown = Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot wait for the stop signal");
        }
    });
    Ok(run_app_with(file, listener, shutdown, reader).await?)
}
