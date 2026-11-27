//! Usage: ostyr-attack-paths <settings.yaml>.


use attack_paths::serve::{block_on_with_grace, run, SHUTDOWN_GRACE};
use std::io::{stderr, Write};
use std::process::ExitCode;


fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match block_on_with_grace(Box::pin(run(&arguments)), SHUTDOWN_GRACE) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
