use hunt_packs::cli::run_cli;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;


fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    Ok(match run_cli(&args, &mut stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            writeln!(stderr(), "{error}")?;
            ExitCode::FAILURE
        }
    })
}
