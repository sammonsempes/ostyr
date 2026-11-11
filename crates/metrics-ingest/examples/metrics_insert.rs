use metrics_ingest::cli::run_cli;
use std::error::Error;
use std::io::stdout;
use std::time::{Instant, SystemTime, UNIX_EPOCH};


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let now_nanos = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let started = Instant::now();
    Ok(run_cli(&args, now_nanos, &|| started.elapsed(), &mut stdout())?)
}
