//! Usage: ostyr-grc <settings.yaml>.


use grc::serve::{exit_code, register_signals, run};
use std::io::{stderr, Write};
use std::process::ExitCode;


#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = run(&arguments, register_signals()?).await;
    let code = exit_code(&result);
    result.err().map_or(Ok(code), |error| writeln!(stderr(), "{error}").map(|()| code))
}
