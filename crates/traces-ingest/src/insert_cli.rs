use crate::cli::{MAX_REQUEST_FILE_BYTES, MAX_SAMPLING_FILE_BYTES};
use crate::run::{run_insert, write_report, RunError};
use crate::sampling::{parse_sampling, SamplingError};
use core_pg::error::PgError;
use core_pg::password::read_limited;
use metrics_ingest::types::ElapsedFn;
use std::io::{self, Write};
use std::path::Path;
use std::str::{from_utf8, Utf8Error};
use thiserror::Error;


pub const INSERT_USAGE: &str = "usage: traces_insert <settings.yaml> <request.pb> <sampling.yaml> <tenant>";


#[derive(Clone, Copy, Debug)]
pub struct InsertArgs<'a> {
    pub settings: &'a str,
    pub request: &'a str,
    pub sampling: &'a str,
    pub tenant: &'a str,
}


#[derive(Debug, Error)]
pub enum InsertCliError {
    #[error("{INSERT_USAGE}")]
    Usage,
    #[error("the request file could not be read")]
    Request(#[source] PgError),
    #[error("the sampling file could not be read")]
    SamplingFile(#[source] PgError),
    #[error("the sampling file is not UTF-8")]
    SamplingText(#[source] Utf8Error),
    #[error("the sampling file is refused")]
    Sampling(#[from] SamplingError),
    #[error(transparent)]
    Run(#[from] RunError),
    #[error("the report could not be written")]
    Output(#[from] io::Error),
    #[error("batch {0} failed, see the report")]
    BatchFailed(usize),
    #[error("the request was refused, see the report")]
    RequestRefused,
}


pub fn insert_files(args: &InsertArgs, now_nanos: u64, elapsed: &ElapsedFn, out: &mut dyn Write) -> Result<(), InsertCliError> {
    let bytes = read_limited(Path::new(args.request), MAX_REQUEST_FILE_BYTES).map_err(InsertCliError::Request)?;
    let sampling_bytes = read_limited(Path::new(args.sampling), MAX_SAMPLING_FILE_BYTES).map_err(InsertCliError::SamplingFile)?;
    let text = from_utf8(&sampling_bytes).map_err(InsertCliError::SamplingText)?;
    let sampling = parse_sampling(text, args.sampling)?;
    let report = run_insert(Path::new(args.settings), &bytes, args.tenant, &sampling, now_nanos, elapsed)?;
    write_report(&report, out)?;
    if report.refusal.is_some() {
        Err(InsertCliError::RequestRefused)
    } else {
        report.failed_batch.map_or(Ok(()), |index| Err(InsertCliError::BatchFailed(index)))
    }
}


/// Decodes the request for the tenant, encodes with `now_nanos` and sends; the report goes to `out`, a failed batch is an error after it.
pub fn run_insert_cli(args: &[String], now_nanos: u64, elapsed: &ElapsedFn, out: &mut dyn Write) -> Result<(), InsertCliError> {
    match args {
        [settings, request, sampling, tenant] => insert_files(
            &InsertArgs {
                settings,
                request,
                sampling,
                tenant,
            },
            now_nanos,
            elapsed,
            out,
        ),
        _ => Err(InsertCliError::Usage),
    }
}


/// One fixed line per failure: no error chain, no server or file content.
pub fn insert_error_text(error: &InsertCliError) -> String {
    match error {
        InsertCliError::Usage => INSERT_USAGE.to_string(),
        InsertCliError::Request(_) => "the request file could not be read".to_string(),
        InsertCliError::SamplingFile(_) | InsertCliError::SamplingText(_) | InsertCliError::Sampling(_) => "the sampling file is refused".to_string(),
        InsertCliError::Output(_) => "the report could not be written".to_string(),
        InsertCliError::BatchFailed(index) => format!("batch {index} failed, see the report"),
        InsertCliError::RequestRefused => "the request was refused, see the report".to_string(),
        InsertCliError::Run(_) => "the settings or the sender are refused".to_string(),
    }
}
