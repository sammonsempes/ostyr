use crate::model::{Limits, MetricKind, SampleRow};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};


pub const NANOS_PER_SECOND: u64 = 1_000_000_000;


pub const NANOS_PER_MILLI: u64 = 1_000_000;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub body: Vec<u8>,
    pub rows: usize,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefusedRow {
    NonFiniteValue,
    RowTooLarge,
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub batches: Vec<Batch>,
    pub refused: BTreeMap<RefusedRow, u64>,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    ZeroBatchRows,
    ZeroBatchBytes,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsertError {
    pub sent: usize,
}


impl Display for RefusedRow {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(match self {
            Self::NonFiniteValue => "non_finite_value",
            Self::RowTooLarge => "row_too_large",
        })
    }
}


impl Error for RefusedRow {}


impl Display for EncodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(match self {
            Self::ZeroBatchRows => "max_batch_rows must be at least 1",
            Self::ZeroBatchBytes => "max_batch_bytes must be at least 1",
        })
    }
}


impl Error for EncodeError {}


impl Display for InsertError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        write!(formatter, "metric batch insert failed after {} batches sent", self.sent)
    }
}


impl Error for InsertError {}


pub struct Accumulator {
    pub batches: Vec<Batch>,
    pub body: Vec<u8>,
    pub rows: usize,
    pub refused: BTreeMap<RefusedRow, u64>,
}


fn kind_name(kind: MetricKind) -> &'static str {
    match kind {
        MetricKind::Gauge => "gauge",
        MetricKind::Counter => "counter",
        MetricKind::Histogram => "histogram",
    }
}


/// ClickHouse reads a quoted `seconds.millis` string as a `DateTime64(3)` unix timestamp.
pub fn timestamp_text(nanos: u64) -> String {
    format!("{}.{:03}", nanos / NANOS_PER_SECOND, (nanos % NANOS_PER_SECOND) / NANOS_PER_MILLI)
}


/// One `JSONEachRow` line (newline included) with the `metric_samples` columns; the tenant comes from the row only.
pub fn encode_row(row: &SampleRow) -> Result<Vec<u8>, RefusedRow> {
    let labels: Map<String, Value> = row
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    if row.value.is_finite() {
        let object = json!({
            "tenant": row.tenant,
            "metric": row.name,
            "unit": row.unit,
            "kind": kind_name(row.kind),
            "labels": labels,
            "@timestamp": timestamp_text(row.timestamp_nanos),
            "value": row.value,
        });
        Ok(format!("{object}\n").into_bytes())
    } else {
        Err(RefusedRow::NonFiniteValue)
    }
}


fn flush(accumulator: Accumulator) -> Accumulator {
    let mut batches = accumulator.batches;
    if accumulator.rows > 0 {
        batches.push(Batch {
            body: accumulator.body,
            rows: accumulator.rows,
        });
    }
    Accumulator {
        batches,
        body: Vec::new(),
        rows: 0,
        refused: accumulator.refused,
    }
}


fn refuse(mut accumulator: Accumulator, reason: RefusedRow) -> Accumulator {
    *accumulator.refused.entry(reason).or_insert(0) += 1;
    accumulator
}


fn append(accumulator: Accumulator, line: Vec<u8>, limits: &Limits) -> Accumulator {
    let full = accumulator.rows >= limits.max_batch_rows || accumulator.body.len() + line.len() > limits.max_batch_bytes;
    let mut ready = if full { flush(accumulator) } else { accumulator };
    ready.body.extend_from_slice(&line);
    ready.rows += 1;
    ready
}


fn add_row(accumulator: Accumulator, row: &SampleRow, limits: &Limits) -> Accumulator {
    match encode_row(row) {
        Err(reason) => refuse(accumulator, reason),
        Ok(line) if line.len() > limits.max_batch_bytes => refuse(accumulator, RefusedRow::RowTooLarge),
        Ok(line) => append(accumulator, line, limits),
    }
}


/// Cuts the rows into batches of at most `max_batch_rows` rows and `max_batch_bytes` bytes; refused rows are counted, never sent.
pub fn encode_rows(rows: &[SampleRow], limits: &Limits) -> Result<Encoded, EncodeError> {
    if limits.max_batch_rows == 0 {
        Err(EncodeError::ZeroBatchRows)
    } else if limits.max_batch_bytes == 0 {
        Err(EncodeError::ZeroBatchBytes)
    } else {
        let start = Accumulator {
            batches: Vec::new(),
            body: Vec::new(),
            rows: 0,
            refused: BTreeMap::new(),
        };
        let done = flush(rows.iter().fold(start, |accumulator, row| add_row(accumulator, row, limits)));
        Ok(Encoded {
            batches: done.batches,
            refused: done.refused,
        })
    }
}


/// Sends each batch in order and stops at the first failure; the sender's text is dropped, only the count of sent batches is reported.
pub fn insert_batches<Sender>(batches: &[Batch], mut send: Sender) -> Result<usize, InsertError>
where
    Sender: FnMut(&[u8]) -> Result<(), String>,
{
    batches
        .iter()
        .enumerate()
        .try_for_each(|(sent, batch)| send(&batch.body).map_err(|_reason| InsertError { sent }))
        .map(|()| batches.len())
}
