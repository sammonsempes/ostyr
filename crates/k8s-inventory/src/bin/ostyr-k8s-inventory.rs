//! Usage: ostyr-k8s-inventory <service.yaml>.


use k8s_inventory::serve::{exit_code, run, stop_signals};
use k8s_inventory::signals::early_reload_signals;
use std::io::{stderr, Write};
use std::process::ExitCode;


#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let reload_signals = early_reload_signals()?;
    let result = run(&arguments, stop_signals()?, reload_signals).await;
    let code = exit_code(&result);
    result.err().map_or(Ok(code), |error| writeln!(stderr(), "{error}").map(|()| code))
}
