use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use traces_ingest::insert_cli::{insert_error_text, run_insert_cli};


fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let now_nanos = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let started = Instant::now();
    Ok(match run_insert_cli(&args, now_nanos, &|| started.elapsed(), &mut stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            writeln!(stderr(), "{}", insert_error_text(&error))?;
            ExitCode::FAILURE
        }
    })
}
