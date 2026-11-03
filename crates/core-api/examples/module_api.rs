use axum::routing::get;
use axum::Router;
use core_api::logging::json_dispatch;
use core_api::model::{Requirement, Rule};
use core_api::server::run_module;
use core_api::types::{AccessTable, ServerHandle};
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::Duration;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


async fn ping() -> &'static str {
    "pong"
}


fn ping_access() -> AccessTable {
    [(
        "GET /example/ping".to_owned(),
        Rule {
            requirement: Requirement::Permission("events.read".to_owned()),
            sensitive: false,
        },
    )]
    .into_iter()
    .collect()
}


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
            match run_module(&arguments, Router::new().route("/example/ping", get(ping)), ping_access(), handle).await {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
