use crate::decode::decode_traces;
use crate::insert::{encode_spans, insert_statement};
use crate::model::{Limits, Refusal};
use crate::sampling::Sampling;
use crate::types::{Dropped, RefusedCounts};
use metrics_ingest::insert::{insert_batches, EncodeError};
use metrics_ingest::send::{statement_sender, SendError};
use metrics_ingest::settings::{load_settings, LoadError, SettingsError};
use metrics_ingest::types::ElapsedFn;
use std::io::{self, Write};
use std::path::Path;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum RunError {
    #[error(transparent)]
    Settings(#[from] LoadError),
    #[error(transparent)]
    Statement(#[from] SettingsError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Send(#[from] SendError),
}


#[derive(Debug)]
pub struct RunReport {
    pub tenant: String,
    pub rows: usize,
    pub dropped: Dropped,
    pub sampled_out: u64,
    pub refusal: Option<Refusal>,
    pub refused: RefusedCounts,
    pub batches_planned: usize,
    pub batches_sent: usize,
    pub failed_batch: Option<usize>,
}


/// Decodes for the authenticated `tenant`, encodes and sends; nothing touches the password or the network when no batch is left.
pub fn run_insert(
    settings_path: &Path,
    request: &[u8],
    tenant: &str,
    sampling: &Sampling,
    now_nanos: u64,
    elapsed: &ElapsedFn,
) -> Result<RunReport, RunError> {
    let settings = load_settings(settings_path)?;
    let statement = insert_statement(&settings.database, &settings.table)?;
    let limits = Limits::default();
    let outcome = decode_traces(request, tenant, &limits, sampling, now_nanos);
    let encoded = encode_spans(&outcome.rows, &limits, now_nanos)?;
    let sent = if encoded.batches.is_empty() {
        Ok(0)
    } else {
        let mut send = statement_sender(&settings, statement, elapsed)?;
        insert_batches(&encoded.batches, |body| send(body).map_err(|error| error.to_string()))
    };
    Ok(RunReport {
        tenant: outcome.tenant,
        rows: outcome.rows.len(),
        dropped: outcome.dropped,
        sampled_out: outcome.sampled_out,
        refusal: outcome.refusal,
        refused: encoded.refused,
        batches_planned: encoded.batches.len(),
        batches_sent: sent.as_ref().map_or_else(|failed| failed.sent, |count| *count),
        failed_batch: sent.err().map(|failed| failed.sent),
    })
}


/// Counts only: no payload text and no server message.
pub fn write_report(report: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "tenant {}", report.tenant)?;
    writeln!(out, "rows {}", report.rows)?;
    writeln!(out, "sampled_out {}", report.sampled_out)?;
    report
        .refusal
        .iter()
        .try_for_each(|refusal| writeln!(out, "request refused {refusal:?}"))?;
    report
        .dropped
        .iter()
        .try_for_each(|(reason, count)| writeln!(out, "dropped {reason} {count}"))?;
    report
        .refused
        .iter()
        .try_for_each(|(reason, count)| writeln!(out, "refused {reason} {count}"))?;
    writeln!(out, "batches planned {}", report.batches_planned)?;
    writeln!(out, "batches sent {}", report.batches_sent)?;
    report.failed_batch.iter().try_for_each(|index| writeln!(out, "failed batch {index}"))
}
