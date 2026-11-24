//! Usage: ostyr-status-page <server.yaml>.


use status_page::service::{run, stop_signals};
use std::io::{stderr, Write};
use std::process::ExitCode;


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments, stop_signals).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
