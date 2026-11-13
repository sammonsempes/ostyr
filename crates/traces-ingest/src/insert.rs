use crate::decode::to_hex;
use crate::model::{Limits, SpanRow, SPAN_ID_BYTES};
use crate::types::{RefusedCounts, SpanId};
use metrics_ingest::insert::{append_line, flush, in_window, Accumulator, Batch, EncodeError};
use metrics_ingest::settings::SettingsError;
use serde_json::{json, Map, Value};
use siem_schema::identifier::quote_identifier;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};


pub const KIND_PREFIX: &str = "SPAN_KIND_";


pub const STATUS_PREFIX: &str = "STATUS_CODE_";


pub const ROOT_PARENT: SpanId = [0; SPAN_ID_BYTES];


pub const INPUT_STRUCTURE: &str = "tenant String, trace_id String, span_id String, parent_span_id String, service_name String, name String, \
kind String, start UInt64, duration_nanos UInt64, status_code String, status_message String, attributes Map(String, String), \
event_count UInt32, link_count UInt32";


pub const COLUMNS: [(&str, &str); COLUMN_COUNT] = [
    ("tenant", "tenant"),
    ("trace_id", "unhex(trace_id)"),
    ("span_id", "unhex(span_id)"),
    ("parent_span_id", "unhex(parent_span_id)"),
    ("service_name", "service_name"),
    ("name", "name"),
    ("kind", "kind"),
    ("start", "fromUnixTimestamp64Nano(toInt64(start), 'UTC')"),
    ("duration_nanos", "duration_nanos"),
    ("status_code", "status_code"),
    ("status_message", "status_message"),
    ("attributes", "attributes"),
    ("event_count", "event_count"),
    ("link_count", "link_count"),
];


pub const COLUMN_COUNT: usize = 14;


/// The column names of the `INSERT`, from the one table that also holds their select expressions.
pub fn column_list() -> String {
    COLUMNS.iter().map(|(column, _)| *column).collect::<Vec<_>>().join(", ")
}


/// The select expressions, in the order of `column_list`: both come from `COLUMNS`, so they cannot drift.
pub fn select_list() -> String {
    COLUMNS.iter().map(|(_, expression)| *expression).collect::<Vec<_>>().join(", ")
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefusedSpan {
    BadDuration,
    RowTooLarge,
    TimestampOutOfRange,
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub batches: Vec<Batch>,
    pub refused: RefusedCounts,
}


impl Display for RefusedSpan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(match self {
            Self::BadDuration => "bad_duration",
            Self::RowTooLarge => "row_too_large",
            Self::TimestampOutOfRange => "timestamp_out_of_range",
        })
    }
}


impl Error for RefusedSpan {}


/// The `INSERT` statement names its columns, so a reordered table cannot shift values; ids travel as hex text and `start` as integer nanoseconds, so the server parses no raw byte and no date text.
pub fn insert_statement(database: &str, table: &str) -> Result<String, SettingsError> {
    Ok(format!(
        "INSERT INTO {}.{} ({}) SELECT {} FROM input('{INPUT_STRUCTURE}') FORMAT JSONEachRow",
        quote_identifier(database)?,
        quote_identifier(table)?,
        column_list(),
        select_list()
    ))
}


/// One `JSONEachRow` line (newline included) with the `trace_spans` columns; the tenant comes from the row only.
pub fn encode_span(row: &SpanRow) -> Result<Vec<u8>, RefusedSpan> {
    row.end_nanos
        .checked_sub(row.start_nanos)
        .ok_or(RefusedSpan::BadDuration)
        .map(|duration| {
            let attributes: Map<String, Value> = row
                .attributes
                .iter()
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect();
            let object = json!({
                "tenant": row.tenant,
                "trace_id": to_hex(&row.trace_id),
                "span_id": to_hex(&row.span_id),
                "parent_span_id": to_hex(&row.parent_span_id.unwrap_or(ROOT_PARENT)),
                "service_name": row.service_name,
                "name": row.name,
                "kind": row.kind.as_str_name().trim_start_matches(KIND_PREFIX).to_lowercase(),
                "start": row.start_nanos,
                "duration_nanos": duration,
                "status_code": row.status_code.as_str_name().trim_start_matches(STATUS_PREFIX).to_lowercase(),
                "status_message": row.status_message,
                "attributes": attributes,
                "event_count": row.event_count,
                "link_count": row.link_count,
            });
            format!("{object}\n").into_bytes()
        })
}


/// Duration, then the time window on `start` (the partition key), then the byte cap of one row.
pub fn admit(row: &SpanRow, now_nanos: u64, limits: &Limits) -> Result<Vec<u8>, RefusedSpan> {
    let line = encode_span(row)?;
    if !in_window(row.start_nanos, now_nanos, limits.retention_seconds, limits.max_future_skew_seconds) {
        Err(RefusedSpan::TimestampOutOfRange)
    } else if line.len() > limits.max_batch_bytes {
        Err(RefusedSpan::RowTooLarge)
    } else {
        Ok(line)
    }
}


/// Cuts rows into batches within the row and byte caps; refused rows are counted, never sent or truncated.
pub fn encode_spans(rows: &[SpanRow], limits: &Limits, now_nanos: u64) -> Result<Encoded, EncodeError> {
    if limits.max_batch_rows == 0 {
        Err(EncodeError::ZeroBatchRows)
    } else if limits.max_batch_bytes == 0 {
        Err(EncodeError::ZeroBatchBytes)
    } else {
        let start = (
            Accumulator {
                batches: Vec::new(),
                body: Vec::new(),
                rows: 0,
            },
            RefusedCounts::new(),
        );
        let (open, refused) = rows
            .iter()
            .fold(start, |(accumulator, mut counts), row| match admit(row, now_nanos, limits) {
                Ok(line) => (append_line(accumulator, &line, limits.max_batch_rows, limits.max_batch_bytes), counts),
                Err(reason) => {
                    *counts.entry(reason).or_insert(0) += 1;
                    (accumulator, counts)
                }
            });
        let closed = if open.rows == 0 { open } else { flush(open) };
        Ok(Encoded {
            batches: closed.batches,
            refused,
        })
    }
}
