//! The `ostyr-web-ui` service: logs as JSON on stdout, serves until the interrupt wait resolves.


use crate::server::serve_web;
use crate::types::InterruptWait;
use core_api::types::ServerHandle;
use std::error::Error;
use std::io::stdout;
use std::path::Path;
use std::time::Duration;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


const USAGE: &str = "usage: ostyr-web-ui <web-ui.yaml>";


pub async fn stop_on(handle: ServerHandle, wait: InterruptWait) {
    match wait.await {
        Ok(()) => handle.graceful_shutdown(Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


/// Logs the bound address once the server listens, so a caller that asked for port 0 can find it.
pub async fn announce(handle: ServerHandle) {
    let address = handle.listening().await;
    address.iter().for_each(|bound| {
        let text = bound.to_string();
        tracing::info!(address = text, "serving");
    });
}


pub async fn run(arguments: &[String], wait: InterruptWait) -> Result<(), Box<dyn Error>> {
    match arguments {
        [path] => {
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_writer(BoxMakeWriter::new(stdout))
                .with_max_level(tracing::Level::INFO)
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;
            let handle = ServerHandle::new();
            tokio::spawn(stop_on(handle.clone(), wait));
            tokio::spawn(announce(handle.clone()));
            serve_web(Path::new(path), handle).await?;
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}
