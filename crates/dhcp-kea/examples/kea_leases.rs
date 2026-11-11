use dhcp_kea::cli::{run, MAX_FOLLOW_POLLS};
use std::env::args;
use std::error::Error;
use std::io::{stderr, stdout};
use std::process::ExitCode;
use std::thread::sleep;


fn main() -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(stderr).try_init()?;
    let arguments: Vec<String> = args().skip(1).collect();
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    Ok(run(&borrowed, &mut stdout().lock(), &mut stderr(), MAX_FOLLOW_POLLS, sleep)?)
}
