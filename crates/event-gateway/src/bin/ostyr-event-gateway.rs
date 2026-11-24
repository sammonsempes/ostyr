//! Usage: ostyr-event-gateway <server.yaml> <gateway.yaml>.


use event_gateway::serve::run;
use std::io::{stderr, Write};
use std::process::ExitCode;


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
