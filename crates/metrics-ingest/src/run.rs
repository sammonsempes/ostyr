use crate::cardinality::CardinalityState;
use crate::decode::decode_request;
use crate::insert::{encode_rows, insert_batches, EncodeError, RefusedRow};
use crate::model::Refusal;
use crate::send::{clickhouse_sender, SendError};
use crate::settings::{load_settings, LoadError};
use crate::types::{Dropped, ElapsedFn};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum RunError {
    #[error("the tenant name is refused")]
    Tenant(#[source] PgError),
    #[error(transparent)]
    Settings(#[from] LoadError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Send(#[from] SendError),
}


#[derive(Debug, Clone, PartialEq)]
pub struct RunReport {
    pub tenant: String,
    pub rows: usize,
    pub dropped: Dropped,
    pub refusal: Option<Refusal>,
    pub refused: BTreeMap<RefusedRow, u64>,
    pub batches_planned: usize,
    pub batches_sent: usize,
    pub failed_batch: Option<usize>,
}


/// The tenant is checked by core-pg's grammar before any I/O; settings are loaded once per run; nothing is sent when no batch is left.
pub fn run_insert(
    settings_path: &Path,
    request: &[u8],
    tenant: &str,
    state: &mut CardinalityState,
    now_nanos: u64,
    elapsed: &ElapsedFn,
) -> Result<RunReport, RunError> {
    let scope = tenant_scope(tenant).map_err(RunError::Tenant)?;
    let settings = load_settings(settings_path)?;
    let outcome = decode_request(request, tenant_of(&scope), &settings.limits, state);
    let encoded = encode_rows(&outcome.rows, &settings.limits, now_nanos)?;
    let sent = if encoded.batches.is_empty() {
        Ok(0)
    } else {
        let mut send = clickhouse_sender(&settings, elapsed)?;
        insert_batches(&encoded.batches, |body| send(body).map_err(|error| error.to_string()))
    };
    Ok(RunReport {
        tenant: outcome.tenant,
        rows: outcome.rows.len(),
        dropped: outcome.dropped,
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
