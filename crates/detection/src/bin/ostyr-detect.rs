//! Usage: ostyr-detect <detection.yaml>.


#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::io::{stderr, Write};
    use std::process::ExitCode;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match detection::serve::service(&arguments) {
        Ok(exit) => ExitCode::from(detection::serve::exit_status(exit)),
        Err(error) => writeln!(stderr(), "{error}").map_or(ExitCode::FAILURE, |()| ExitCode::FAILURE),
    }
}


#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
