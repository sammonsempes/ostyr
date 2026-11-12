use crate::decode::{decode_traces, to_hex};
use crate::model::{Limits, Outcome};
use crate::sampling::{parse_sampling, SamplingError};
use core_pg::error::PgError;
use core_pg::password::read_limited;
use std::io::{self, Write};
use std::path::Path;
use std::str::{from_utf8, Utf8Error};
use thiserror::Error;


pub const MAX_REQUEST_FILE_BYTES: u64 = 67_108_864;


pub const MAX_SAMPLING_FILE_BYTES: u64 = 65_536;


pub const MAX_PRINTED_ROWS: usize = 10;


pub const USAGE: &str = "usage: traces_decode <request.pb> <sampling.yaml> <tenant>";


#[derive(Debug, Error)]
pub enum CliError {
    #[error("{USAGE}")]
    Usage,
    #[error("the request file could not be read")]
    Request(#[source] PgError),
    #[error("the sampling file could not be read")]
    SamplingFile(#[source] PgError),
    #[error("the sampling file is not UTF-8")]
    SamplingText(#[source] Utf8Error),
    #[error("the sampling file is refused")]
    Sampling(#[from] SamplingError),
    #[error("the report could not be written")]
    Output(#[from] io::Error),
}


/// Counts first, then the first rows; payload text appears only in the printed rows, which passed the text checks.
pub fn write_report(outcome: &Outcome, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "tenant {}", outcome.tenant)?;
    writeln!(out, "rows {}", outcome.rows.len())?;
    writeln!(out, "sampled_out {}", outcome.sampled_out)?;
    writeln!(out, "refusal {:?}", outcome.refusal)?;
    outcome
        .dropped
        .iter()
        .try_for_each(|(reason, count)| writeln!(out, "dropped {reason} {count}"))?;
    outcome.rows.iter().take(MAX_PRINTED_ROWS).try_for_each(|row| {
        writeln!(
            out,
            "row trace {} span {} service {} name {} status {:?} start {} end {} attributes {}",
            to_hex(&row.trace_id),
            to_hex(&row.span_id),
            row.service_name,
            row.name,
            row.status_code,
            row.start_nanos,
            row.end_nanos,
            row.attributes.len()
        )
    })
}


pub fn run_files(request: &str, sampling: &str, tenant: &str, now_nanos: u64, out: &mut dyn Write) -> Result<(), CliError> {
    let bytes = read_limited(Path::new(request), MAX_REQUEST_FILE_BYTES).map_err(CliError::Request)?;
    let sampling_bytes = read_limited(Path::new(sampling), MAX_SAMPLING_FILE_BYTES).map_err(CliError::SamplingFile)?;
    let text = from_utf8(&sampling_bytes).map_err(CliError::SamplingText)?;
    let parsed = parse_sampling(text, sampling)?;
    let outcome = decode_traces(&bytes, tenant, &Limits::default(), &parsed, now_nanos);
    write_report(&outcome, out)?;
    Ok(())
}


pub fn run_cli(args: &[String], now_nanos: u64, out: &mut dyn Write) -> Result<(), CliError> {
    match args {
        [request, sampling, tenant] => run_files(request, sampling, tenant, now_nanos, out),
        _ => Err(CliError::Usage),
    }
}
