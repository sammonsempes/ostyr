use crate::model::Refusal;
use crate::run::{run_insert_with, RunError, RunReport};
use crate::sampling::Sampling;
use crate::settings::TracesSettings;
use crate::types::AdmittedFn;
use metrics_ingest::types::ElapsedFn;
use opentelemetry_proto::tonic::collector::trace::v1::{ExportTracePartialSuccess, ExportTraceServiceResponse};
use prost::Message;
use siem_ingest::error::InsertClass;


pub const STATUS_OK: u16 = 200;


pub const STATUS_BAD_REQUEST: u16 = 400;


pub const STATUS_UNAUTHORIZED: u16 = 401;


pub const STATUS_TOO_LARGE: u16 = 413;


pub const STATUS_INTERNAL: u16 = 500;


pub const STATUS_UNAVAILABLE: u16 = 503;


pub const PROTOBUF: &str = "application/x-protobuf";


pub const PLAIN: &str = "text/plain";


pub const TEXT_REFUSED: &str = "the request was refused";


pub const TEXT_TOO_LARGE: &str = "the request is over the size limit";


pub const TEXT_REVOKED: &str = "the sender is no longer admitted";


pub const TEXT_UNAVAILABLE: &str = "the span store is unavailable, retry later";


pub const RETRYABLE: [InsertClass; 2] = [InsertClass::Unavailable, InsertClass::Timeout];


pub const TEXT_FAILED: &str = "the export failed";


/// What the route answers: a status, a fixed body, and whether the client is told to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub retry_after: bool,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}


pub fn fixed(status: u16, text: &str, retry_after: bool) -> Reply {
    Reply {
        status,
        retry_after,
        content_type: PLAIN,
        body: text.as_bytes().to_vec(),
    }
}


/// Counts and reason names only, never payload text.
pub fn partial_text(report: &RunReport, unsent: u64) -> String {
    let dropped: Vec<String> = report.dropped.iter().map(|(reason, count)| format!("{reason} {count}")).collect();
    let refused: Vec<String> = report.refused.iter().map(|(reason, count)| format!("{reason} {count}")).collect();
    format!("dropped [{}], refused [{}], not stored {unsent}", dropped.join(", "), refused.join(", "))
}


/// `rejected_spans` = dropped, encode-refused and the rows of unsent batches; sampled-out spans are not rejected.
pub fn accepted(report: &RunReport) -> Reply {
    let unsent = u64::try_from(report.unsent_rows).unwrap_or(u64::MAX);
    let rejected = report
        .dropped
        .values()
        .chain(report.refused.values())
        .fold(unsent, |total, count| total.saturating_add(*count));
    let partial = (rejected > 0).then(|| ExportTracePartialSuccess {
        rejected_spans: i64::try_from(rejected).unwrap_or(i64::MAX),
        error_message: partial_text(report, unsent),
    });
    Reply {
        status: STATUS_OK,
        retry_after: false,
        content_type: PROTOBUF,
        body: ExportTraceServiceResponse { partial_success: partial }.encode_to_vec(),
    }
}


/// The status of a finished run: refusals 400 or 413, a revoked sender 401, nothing stored 503 or 500, else 200 with the partial count.
pub fn reply_of(report: &RunReport) -> Reply {
    let nothing_stored = report.failed_batch.is_some() && report.batches_sent == 0;
    let retryable = report.failure.is_some_and(|class| RETRYABLE.contains(&class));
    match &report.refusal {
        Some(Refusal::TooLarge { .. }) => fixed(STATUS_TOO_LARGE, TEXT_TOO_LARGE, false),
        Some(_) => fixed(STATUS_BAD_REQUEST, TEXT_REFUSED, false),
        None if report.revoked && nothing_stored => fixed(STATUS_UNAUTHORIZED, TEXT_REVOKED, false),
        None if retryable && nothing_stored => fixed(STATUS_UNAVAILABLE, TEXT_UNAVAILABLE, true),
        None if nothing_stored => fixed(STATUS_INTERNAL, TEXT_FAILED, false),
        None => accepted(report),
    }
}


/// A fixed line for the log: a send failure through its fixed `Display`, any other error as a category.
pub fn error_text(error: &RunError) -> String {
    match error {
        RunError::Send(send) => send.to_string(),
        RunError::Settings(_) | RunError::Statement(_) => "the settings are refused".to_owned(),
        RunError::Encode(_) => "the batch limits are refused".to_owned(),
    }
}


/// Decodes and stores one export on the given snapshots for the authenticated `tenant`; `admitted` is the sender's live check.
pub fn receive_export(
    traces: &TracesSettings,
    sampling: &Sampling,
    request: &[u8],
    tenant: &str,
    admitted: &AdmittedFn,
    now_nanos: u64,
    elapsed: &ElapsedFn,
) -> Reply {
    match run_insert_with(traces, request, tenant, sampling, now_nanos, elapsed, admitted) {
        Ok(report) => reply_of(&report),
        Err(error) => {
            let reason = error_text(&error);
            tracing::warn!(reason, "traces export failed");
            fixed(STATUS_INTERNAL, TEXT_FAILED, false)
        }
    }
}
