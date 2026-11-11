use metrics_ingest::cli::{error_text, run_cli};
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};


fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let now_nanos = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let started = Instant::now();
    let settings_path = args.first().map_or("", String::as_str);
    Ok(match run_cli(&args, now_nanos, &|| started.elapsed(), &mut stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            writeln!(stderr(), "{}", error_text(&error, settings_path))?;
            ExitCode::FAILURE
        }
    })
}
