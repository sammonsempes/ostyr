//! Usage: `event_gateway <server.yaml> <gateway.yaml>`. The server file is the `channel_server` one (its `events_file` is not used here).
use agent_channel::server_app::{bind_server, load_server_file};
use event_gateway::run::{load_gateway_file, run_gateway};
use std::error::Error;
use std::path::Path;


const GATEWAY_ARGUMENT: usize = 2;


const USAGE: &str = "usage: event_gateway <server.yaml> <gateway.yaml>";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).try_init()?;
    let server_path = std::env::args().nth(1).ok_or(USAGE)?;
    let gateway_path = std::env::args().nth(GATEWAY_ARGUMENT).ok_or(USAGE)?;
    let server = load_server_file(Path::new(&server_path))?;
    let gateway = load_gateway_file(Path::new(&gateway_path))?;
    let listener = bind_server(&server).await?;
    let shutdown = Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot wait for the stop signal");
        }
    });
    Ok(run_gateway(server, gateway, listener, shutdown).await?)
}
