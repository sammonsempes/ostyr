use core_api::example::{example_access, example_document, example_router};
use core_api::logging::json_dispatch;
use core_api::server::run_module;
use core_api::types::ServerHandle;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::Duration;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


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
    match tracing::dispatcher::set_global_default(json_dispatch(BoxMakeWriter::new(stdout))) {
        Ok(()) => {
            let handle = ServerHandle::new();
            tokio::spawn(stop_on_interrupt(handle.clone()));
            match run_module(&arguments, example_router(), example_access(), vec![example_document()], handle).await {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
