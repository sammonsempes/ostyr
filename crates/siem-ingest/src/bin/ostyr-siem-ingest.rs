//! Usage: ostyr-siem-ingest <settings.yaml>.


use siem_ingest::serve::execute;
use std::process::ExitCode;


fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(execute(&arguments))
}
