//! Usage: `channel_server <config.yaml>`. Replace the revocation file atomically (write a temporary file, then rename it): an in-place edit can be read half written.
use agent_channel::server_app::{bind_relay, bind_server, file_events, load_server_file, run_server};
use std::error::Error;
use std::path::Path;


const USAGE: &str = "usage: channel_server <config.yaml>";


const DEBUG_VARIABLE: &str = "CHANNEL_SERVER_DEBUG";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let level = if std::env::var_os(DEBUG_VARIABLE).is_some() {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).with_writer(std::io::stderr).try_init()?;
    let path = std::env::args().nth(1).ok_or(USAGE)?;
    let file = load_server_file(Path::new(&path))?;
    let listener = bind_server(&file).await?;
    let relay = bind_relay(&file).await?;
    let events = file_events(&file)?;
    let shutdown = Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot wait for the stop signal");
        }
    });
    Ok(run_server(file, listener, relay, shutdown, events, None).await?)
}
