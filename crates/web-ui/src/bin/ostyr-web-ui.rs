//! Usage: ostyr-web-ui <web-ui.yaml>.


use std::io::{stderr, Write};
use std::process::ExitCode;
use web_ui::serve::run;


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments, Box::pin(tokio::signal::ctrl_c())).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
