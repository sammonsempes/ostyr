use ecs_normalise::cli::run_reporting;
use std::env::args;
use std::io::{stderr, stdin, stdout};
use std::process::ExitCode;


fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = args().skip(1).collect();
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    run_reporting(&borrowed, &mut stdin().lock(), &mut stdout().lock(), &mut stderr())
}
