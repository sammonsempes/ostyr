//! Usage: `status_server <server.yaml> <listen-address>`; the settings file named in it is reloaded on change.
use status_page::app::{run_app, AppFile};
use std::error::Error;
use std::path::Path;
use tokio::net::TcpListener;


const USAGE: &str = "usage: status_server <server.yaml> <listen-address>";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(USAGE)?;
    let address = args.next().ok_or(USAGE)?;
    let file: AppFile = core_config::load::load_file(Path::new(&path))?;
    let listener = TcpListener::bind(address).await?;
    let shutdown = Box::pin(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot wait for the stop signal");
        }
    });
    Ok(run_app(file, listener, shutdown).await?)
}
