use breached_passwords::cli::run_reporting;
use std::io::{stderr, stdout};
use std::process::ExitCode;


fn main() -> Result<ExitCode, Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_writer(stderr)
        .with_max_level(tracing::Level::TRACE)
        .try_init()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    Ok(run_reporting(&borrowed, &mut stdout(), &mut stderr())?)
}
