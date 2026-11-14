use remote_shell::recording_cli::run_record_cli;
use std::error::Error;
use std::io::{stderr, stdin, stdout, Write};
use std::process::ExitCode;


fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    Ok(match run_record_cli(&args, &mut stdin().lock(), &mut stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            writeln!(stderr(), "{error}")?;
            ExitCode::FAILURE
        }
    })
}
