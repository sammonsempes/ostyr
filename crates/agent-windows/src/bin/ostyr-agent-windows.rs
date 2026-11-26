//! Usage: ostyr-agent-windows <state-dir> <spool>.


use agent_windows::serve::{error_line, exit_code, run, stop_signals};
use std::io::{stderr, Write};
use std::process::ExitCode;


#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = run(&arguments, stop_signals()?).await;
    let code = exit_code(&result);
    result
        .err()
        .map_or(Ok(code), |error| writeln!(stderr(), "{}", error_line(&error)).map(|()| code))
}
