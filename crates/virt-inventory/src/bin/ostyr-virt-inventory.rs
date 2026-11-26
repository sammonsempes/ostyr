//! Usage: ostyr-virt-inventory <settings.yaml>.


use std::io::{stderr, Write};
use std::process::ExitCode;
use virt_inventory::serve::{exit_code, run, stop_signals};


#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = run(&arguments, stop_signals()?).await;
    let code = exit_code(&result);
    result.err().map_or(Ok(code), |error| writeln!(stderr(), "{error}").map(|()| code))
}
