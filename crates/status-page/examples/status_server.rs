//! Usage: `status_server <server.yaml> <listen-address>`; the settings file named in it is reloaded on change, and with `pg_file` the page comes from the store.
use core_pg::connect::connect;
use core_pg::scope::TenantScope;
use core_pg::settings::load_settings;
use status_page::app::{run_app_with, AppFile};
use status_page::error::StoreError;
use status_page::pg::execute;
use status_page::publish::{read_within, settings_cut};
use status_page::store::{read_published, MAX_PUBLISHED};
use status_page::store_model::{PublishedRead, Statement};
use status_page::types::IncidentReadFn;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpListener;


const USAGE: &str = "usage: status_server <server.yaml> <listen-address>";


/// One read: the core-pg settings are loaded afresh, one connection is opened (connect timeout) and queried under the statement timeout.
async fn read_once(pg_file: &Path, scope: &TenantScope, services: &[String]) -> Result<PublishedRead, StoreError> {
    let settings = load_settings(pg_file)?;
    let deadline = Duration::from_secs(settings.statement_timeout_secs);
    let cut = settings_cut(settings.connect_timeout_secs, settings.statement_timeout_secs);
    read_within(cut, async {
        let client = connect(&settings).await?;
        let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&client, query_scope.clone(), statement, deadline);
        read_published(&mut exec, scope, services, MAX_PUBLISHED).await
    })
    .await
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
