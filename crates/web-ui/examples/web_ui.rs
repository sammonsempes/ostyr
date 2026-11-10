use core_api::types::ServerHandle;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use web_ui::server::serve_web;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


async fn stop_on_interrupt(handle: ServerHandle) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => handle.graceful_shutdown(Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    tracing_subscriber::fmt()
        .json()
        .with_writer(BoxMakeWriter::new(stdout))
        .with_max_level(tracing::Level::INFO)
        .init();
    match arguments.as_slice() {
        [path] => {
            let handle = ServerHandle::new();
            tokio::spawn(stop_on_interrupt(handle.clone()));
            match serve_web(Path::new(path), handle).await {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        _ => writeln!(stderr(), "usage: web_ui <web-ui.yaml>").map(|()| ExitCode::FAILURE),
    }
}
