//! The `ostyr-status-page` service: the public page server on the address of its server file, stopped by SIGINT or SIGTERM; logs on stderr.


use crate::app::{run_app_with, AppFile};
use crate::error::{StatusPageError, StoreError};
use crate::pg::execute;
use crate::publish::{read_within, settings_cut};
use crate::store::{read_published, MAX_PUBLISHED};
use crate::store_model::{PublishedRead, Statement};
use crate::types::{IncidentReadFn, InterruptWait, SignalsFn};
use core_config::load::load_file;
use core_pg::connect::connect;
use core_pg::scope::TenantScope;
use core_pg::settings::load_settings;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpListener;


pub const USAGE: &str = "usage: ostyr-status-page <server.yaml>";


/// One read: the core-pg settings are loaded afresh, one connection is opened (connect timeout) and queried under the statement timeout.
pub async fn read_once(pg_file: &Path, scope: &TenantScope, services: &[String]) -> Result<PublishedRead, StoreError> {
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


pub fn pg_reader(pg_file: PathBuf) -> IncidentReadFn {
    Box::new(move |scope, services| {
        let path = pg_file.clone();
        Box::pin(async move { read_once(&path, &scope, &services).await })
    })
}


/// Registers SIGINT and SIGTERM at once, so a signal sent after the call is never lost; the future resolves on the first.
#[cfg(unix)]
pub fn stop_signals() -> io::Result<InterruptWait> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = interrupt.recv() => Ok(()),
            _ = terminate.recv() => Ok(()),
        }
    }))
}


#[cfg(not(unix))]
pub fn stop_signals() -> io::Result<InterruptWait> {
    Ok(Box::pin(tokio::signal::ctrl_c()))
}


/// Resolves when the wait does; a failing wait is logged and also stops the server.
pub async fn stop_on(wait: InterruptWait) {
    if let Err(error) = wait.await {
        tracing::warn!(%error, "cannot wait for the stop signal");
    }
}


pub async fn run(arguments: &[String], signals: SignalsFn) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    let wait = signals()?;
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(io::stderr).with_ansi(false).finish())?;
    start(Path::new(settings_file), wait).await
}


/// Serves the page on `listen_address` of the server file (start only, required) until the wait resolves.
pub async fn start(settings_file: &Path, wait: InterruptWait) -> Result<(), Box<dyn Error>> {
    let file: AppFile = load_file(settings_file)?;
    let address = file
        .listen_address
        .ok_or_else(|| StatusPageError::InvalidSettings("listen_address is required".to_owned()))?;
    if !file.audit_file.is_absolute() {
        Err(StatusPageError::InvalidSettings("audit_file must be an absolute path".to_owned()))?;
    }
    let reader = file.pg_file.clone().map(pg_reader);
    let listener = TcpListener::bind(address).await?;
    let bound = listener.local_addr()?.to_string();
    tracing::info!(address = bound, "listening");
    run_app_with(file, listener, Box::pin(stop_on(wait)), reader).await?;
    Ok(())
}
