//! Usage: ostyr-hunt <hunt.yaml>.


use hunt_packs::serve::{runtime, serve_hunt, wait_for_signal};
use std::io::{stderr, Write};
use std::process::ExitCode;


fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match runtime()?.block_on(serve_hunt(&arguments, Box::pin(wait_for_signal()))) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
