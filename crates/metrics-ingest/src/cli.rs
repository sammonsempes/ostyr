use crate::cardinality::CardinalityState;
use crate::run::{run_insert, write_report, RunError};
use crate::settings::{LoadError, SettingsError};
use crate::types::ElapsedFn;
use core_pg::error::PgError;
use core_pg::password::read_limited;
use std::io::{self, Write};
use std::path::Path;
use thiserror::Error;


pub const MAX_REQUEST_FILE_BYTES: u64 = 67_108_864;


pub const USAGE: &str = "usage: metrics_insert <settings.yaml> <request.pb> <tenant>";


#[derive(Debug, Error)]
pub enum CliError {
    #[error("{USAGE}")]
    Usage,
    #[error("the request file could not be read")]
    Request(#[source] PgError),
    #[error(transparent)]
    Run(#[from] RunError),
    #[error("the report could not be written")]
    Output(#[from] io::Error),
    #[error("batch {0} failed, see the report")]
    BatchFailed(usize),
}


pub fn run_files(settings: &str, request: &str, tenant: &str, now_nanos: u64, elapsed: &ElapsedFn, out: &mut dyn Write) -> Result<(), CliError> {
    let bytes = read_limited(Path::new(request), MAX_REQUEST_FILE_BYTES).map_err(CliError::Request)?;
    let mut state = CardinalityState::default();
    let report = run_insert(Path::new(settings), &bytes, tenant, &mut state, now_nanos, elapsed)?;
    write_report(&report, out)?;
    report.failed_batch.map_or(Ok(()), |index| Err(CliError::BatchFailed(index)))
}


/// Decodes the request file for the tenant, encodes with `now_nanos` and sends; the report goes to `out`, a failed batch is an error after it.
pub fn run_cli(args: &[String], now_nanos: u64, elapsed: &ElapsedFn, out: &mut dyn Write) -> Result<(), CliError> {
    match args {
        [settings, request, tenant] => run_files(settings, request, tenant, now_nanos, elapsed, out),
        _ => Err(CliError::Usage),
    }
}


/// One fixed line per failure: no error chain, no server or file content; only the settings path (and a limit field name) is named.
pub fn error_text(error: &CliError, settings_path: &str) -> String {
    match error {
        CliError::Usage => USAGE.to_string(),
        CliError::Request(_) => "the request file could not be read".to_string(),
        CliError::Output(_) => "the report could not be written".to_string(),
        CliError::BatchFailed(index) => format!("batch {index} failed, see the report"),
        CliError::Run(RunError::Tenant(_)) => "the tenant name is refused".to_string(),
        CliError::Run(RunError::Settings(LoadError::Config(_))) => format!("the settings file {settings_path} could not be loaded"),
        CliError::Run(RunError::Settings(LoadError::Invalid(SettingsError::Limit { field, .. }))) => {
            format!("the settings file {settings_path} refuses limits.{field}")
        }
        CliError::Run(RunError::Settings(LoadError::Invalid(_))) => format!("the settings file {settings_path} is invalid"),
        CliError::Run(RunError::Encode(_)) => "the rows could not be encoded".to_string(),
        CliError::Run(RunError::Send(_)) => "the sender could not be built".to_string(),
    }
}
