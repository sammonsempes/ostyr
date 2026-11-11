use metric_alerts::fetch_cli::run_cli;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};


fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(match run_cli(&args, now, &mut stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            writeln!(stderr(), "{error}")?;
            ExitCode::FAILURE
        }
    })
}
