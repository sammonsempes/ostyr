//! The `ostyr-agent-linux` entry point: arguments, log subscriber, the agent until `SIGTERM`, the totals on stdout.
use crate::app::run_linux;
use crate::error::ServeError;
use crate::model::{Totals, MAX_POLLS};
use crate::sensor::run_command;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;


/// The one settings file path; anything else is a usage error.
pub fn parse_args(args: &[String]) -> Result<PathBuf, ServeError> {
    match args {
        [path] => Ok(PathBuf::from(path)),
        _ => Err(ServeError::Usage),
    }
}


pub async fn run_main(args: &[String]) -> Result<Totals, ServeError> {
    let path = parse_args(args)?;
    let totals = run_linux(&path, MAX_POLLS, &|delay: Duration| Box::pin(tokio::time::sleep(delay)), run_command).await?;
    Ok(totals)
}


/// Writes the totals of a clean end to `out` and the one-line error of any other to `err`; a failed write is logged and fails the exit.
pub fn exit_code(result: Result<Totals, ServeError>, out: &mut impl Write, err: &mut impl Write) -> ExitCode {
    let written = match &result {
        Ok(totals) => writeln!(out, "{totals:?}"),
        Err(error) => writeln!(err, "ostyr-agent-linux: {error}"),
    };
    let write_failed = written
        .as_ref()
        .err()
        .inspect(|error| tracing::error!(%error, "final line not written"))
        .is_some();
    ExitCode::from(u8::from(result.is_err() || write_failed))
}


pub async fn main_exit(args: Vec<String>) -> ExitCode {
    let subscriber = tracing_subscriber::fmt().with_writer(io::stderr).finish();
    let installed = tracing::subscriber::set_global_default(subscriber).is_ok();
    tracing::debug!(installed, "log subscriber");
    let result = run_main(&args).await;
    exit_code(result, &mut io::stdout(), &mut io::stderr())
}
