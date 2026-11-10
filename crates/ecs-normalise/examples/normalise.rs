use ecs_normalise::cli::{log_dispatch, run_reporting};
use std::env::args;
use std::io::{stderr, stdin, stdout};
use std::process::ExitCode;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    tracing::dispatcher::set_global_default(log_dispatch(BoxMakeWriter::new(stderr)))?;
    let arguments: Vec<String> = args().skip(1).collect();
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    Ok(run_reporting(&borrowed, &mut stdin().lock(), &mut stdout().lock(), &mut stderr())?)
}
