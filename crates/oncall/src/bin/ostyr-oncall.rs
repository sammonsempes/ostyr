//! Usage: ostyr-oncall <settings.yaml>.


use oncall::serve::{finish_code, interrupt_wait, run_service};
use std::io::stderr;
use std::process::ExitCode;


#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = run_service(&arguments, interrupt_wait()).await;
    finish_code(result, &mut stderr()).map(ExitCode::from)
}
