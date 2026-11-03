use sigma_sql::cli::run_reporting;
use std::io::{stderr, stdout};
use std::process::ExitCode;


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_reporting(&borrowed, &mut stdout(), &mut stderr())
}
