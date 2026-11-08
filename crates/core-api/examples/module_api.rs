use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::example::{example_access, example_document, example_router};
use core_api::logging::reloadable_dispatch;
use core_api::server::{new_listener, run_module, stop_listener};
use core_api::types::SharedListener;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::Duration;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


async fn stop_on_interrupt(listener: SharedListener) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => stop_listener(&listener, Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (dispatch, log) = reloadable_dispatch(BoxMakeWriter::new(stdout), DEFAULT_LOG_LEVEL);
    match tracing::dispatcher::set_global_default(dispatch) {
        Ok(()) => {
            let listener = new_listener();
            tokio::spawn(stop_on_interrupt(listener.clone()));
            match run_module(
                &arguments,
                example_router(),
                example_access(),
                vec![example_document()],
                listener,
                Some(log),
            )
            .await
            {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
