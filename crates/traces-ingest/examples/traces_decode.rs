use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use traces_ingest::cli::run_cli;


fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let now_nanos = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    Ok(match run_cli(&args, now_nanos, &mut stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            writeln!(stderr(), "{error}")?;
            ExitCode::FAILURE
        }
    })
}
