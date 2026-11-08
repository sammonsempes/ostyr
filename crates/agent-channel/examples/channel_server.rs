//! Usage: `channel_server <config.yaml>`. Replace the revocation file atomically (write a temporary file, then rename it): an in-place edit can be read half written.
use agent_channel::server_app::{bind_server, load_server_file, run_server};
use std::error::Error;
use std::path::Path;


const USAGE: &str = "usage: channel_server <config.yaml>";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).try_init()?;
    let path = std::env::args().nth(1).ok_or(USAGE)?;
    let file = load_server_file(Path::new(&path))?;
    let listener = bind_server(&file).await?;
    let shutdown = Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot wait for the stop signal");
        }
    });
    Ok(run_server(file, listener, shutdown).await?)
}
