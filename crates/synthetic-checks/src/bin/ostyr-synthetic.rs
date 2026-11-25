//! Usage: ostyr-synthetic <service.yaml>.


use std::io::stderr;
use std::process::ExitCode;
use synthetic_checks::serve::{finish_code, run_service, stop_on_signals};


fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = run_service(&arguments, stop_on_signals);
    finish_code(result, &mut stderr()).map(ExitCode::from)
}
