//! The `ostyr-event-gateway` service: the agent channel with the JetStream sink until SIGINT or SIGTERM; logs on stderr.


use crate::run::{load_gateway_file, run_gateway};
use agent_channel::server_app::{bind_relay, bind_server, load_server_file};
use agent_channel::types::ShutdownSignal;
use siem_ingest::logging::build_subscriber;
use std::error::Error;
use std::io::stderr;
use std::path::Path;


pub const USAGE: &str = "usage: ostyr-event-gateway <server.yaml> <gateway.yaml>";


pub const LOG_VARIABLE: &str = "RUST_LOG";


/// Resolves on SIGINT or SIGTERM; both are registered before it returns, so a signal sent after it never takes the default action.
#[cfg(unix)]
pub fn stop_signal() -> std::io::Result<ShutdownSignal> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
    }))
}


#[cfg(not(unix))]
pub fn stop_signal() -> std::io::Result<ShutdownSignal> {
    Ok(Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot wait for the stop signal");
        }
    }))
}


/// `arguments` are the server file and the gateway file; any other count is the usage error.
pub async fn run(arguments: &[String]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (server_path, gateway_path) = match arguments {
        [server, gateway] => Ok((server, gateway)),
        _ => Err(USAGE),
    }?;
    let directives = std::env::var(LOG_VARIABLE).ok();
    tracing::subscriber::set_global_default(build_subscriber(stderr, directives.as_deref())?)?;
    let server = load_server_file(Path::new(server_path))?;
    let gateway = load_gateway_file(Path::new(gateway_path))?;
    let listener = bind_server(&server).await?;
    let relay = bind_relay(&server).await?;
    let address = listener.local_addr()?;
    let stop = stop_signal()?;
    tracing::info!(%address, "serving");
    Ok(run_gateway(server, gateway, listener, relay, stop).await?)
}
