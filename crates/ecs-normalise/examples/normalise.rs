use ecs_normalise::cli::run_reporting;
use std::io::{stderr, stdin, stdout};
use std::process::ExitCode;


fn main() -> std::io::Result<ExitCode> {
    run_reporting(&mut stdin().lock(), &mut stdout().lock(), &mut stderr())
}
