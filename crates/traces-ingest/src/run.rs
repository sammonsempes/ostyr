use crate::decode::decode_traces;
use crate::insert::{insert_statement, stream_spans};
use crate::model::Refusal;
use crate::sampling::Sampling;
use crate::settings::{load_traces_settings, to_metrics_settings};
use crate::types::{Dropped, RefusedCounts};
use metrics_ingest::insert::{Batch, EncodeError};
use metrics_ingest::send::{statement_sender, SendError};
use metrics_ingest::settings::{LoadError, SettingsError};
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
    let traces = load_traces_settings(settings_path)?;
    let statement = insert_statement(&traces.database, &traces.table)?;
    let outcome = decode_traces(request, tenant, &traces.limits, sampling, now_nanos);
    let row_count = outcome.rows.len();
    let settings = to_metrics_settings(&traces);
    let mut link = None;
    let mut planned = 0;
    let mut sent = 0;
    let mut failed = None;
    let mut emit = |batch: Batch| {
        planned += 1;
        let delivered = failed.is_none()
            && match link.get_or_insert_with(|| statement_sender(&settings, statement.clone(), elapsed)) {
                Ok(send) => send(&batch.body).is_ok(),
                Err(_) => false,
            };
        if delivered {
            sent += 1;
        } else if failed.is_none() {
            failed = Some(sent);
        }
    };
    let refused = stream_spans(outcome.rows, &traces.limits, now_nanos, &mut emit)?;
    link.and_then(Result::err).map_or(Ok(()), |error| Err(RunError::Send(error)))?;
    Ok(RunReport {
        tenant: outcome.tenant,
        rows: row_count,
        dropped: outcome.dropped,
        sampled_out: outcome.sampled_out,
        refusal: outcome.refusal,
        refused,
        batches_planned: planned,
        batches_sent: sent,
        failed_batch: failed,
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
