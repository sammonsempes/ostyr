use crate::model::{Limits, MetricKind, SampleRow};
use crate::types::Groups;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use time::{Duration, OffsetDateTime};


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
    TimestampOutOfRange,
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
            Self::TimestampOutOfRange => "timestamp_out_of_range",
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
}


pub struct Moment {
    pub year: i32,
    pub month: u8,
    pub text: String,
}


fn kind_name(kind: MetricKind) -> &'static str {
    match kind {
        MetricKind::Gauge => "gauge",
        MetricKind::Counter => "counter",
        MetricKind::Histogram => "histogram",
    }
}


/// Splits a unix time in nanoseconds into its UTC month and the `YYYY-MM-DD hh:mm:ss.mmm` text that `basic` date parsing reads.
pub fn moment(nanos: u64) -> Moment {
    let seconds = (nanos / NANOS_PER_SECOND) as i64;
    let at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(seconds);
    let millis = (nanos % NANOS_PER_SECOND) / NANOS_PER_MILLI;
    Moment {
        year: at.year(),
        month: u8::from(at.month()),
        text: format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second(),
            millis
        ),
    }
}


/// True when the sample time is no older than the raw retention and no more than the future skew ahead of `now_nanos`.
pub fn in_range(nanos: u64, now_nanos: u64, limits: &Limits) -> bool {
    in_window(nanos, now_nanos, limits.raw_retention_seconds, limits.max_future_skew_seconds)
}


/// True when `nanos` is no older than `retention_seconds` and no more than `skew_seconds` ahead of `now_nanos`.
pub fn in_window(nanos: u64, now_nanos: u64, retention_seconds: u64, skew_seconds: u64) -> bool {
    let oldest = now_nanos.saturating_sub(retention_seconds.saturating_mul(NANOS_PER_SECOND));
    let newest = now_nanos.saturating_add(skew_seconds.saturating_mul(NANOS_PER_SECOND));
    nanos >= oldest && nanos <= newest
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
            "@timestamp": moment(row.timestamp_nanos).text,
            "value": row.value,
        });
        Ok(format!("{object}\n").into_bytes())
    } else {
        Err(RefusedRow::NonFiniteValue)
    }
}


/// Closes the open batch and starts an empty one.
pub fn flush(accumulator: Accumulator) -> Accumulator {
    let mut batches = accumulator.batches;
    batches.push(Batch {
        body: accumulator.body,
        rows: accumulator.rows,
    });
    Accumulator {
        batches,
        body: Vec::new(),
        rows: 0,
    }
}


fn refuse(refused: &mut BTreeMap<RefusedRow, u64>, reason: RefusedRow) {
    *refused.entry(reason).or_insert(0) += 1;
}


fn append(accumulator: Accumulator, line: &[u8], limits: &Limits) -> Accumulator {
    append_line(accumulator, line, limits.max_batch_rows, limits.max_batch_bytes)
}


/// Adds one line to the open batch, closing it first when the row or byte cap would be passed.
pub fn append_line(accumulator: Accumulator, line: &[u8], max_rows: usize, max_bytes: usize) -> Accumulator {
    let full = accumulator.rows >= max_rows || accumulator.body.len() + line.len() > max_bytes;
    let mut ready = if full { flush(accumulator) } else { accumulator };
    ready.body.extend_from_slice(line);
    ready.rows += 1;
    ready
}


fn admit(row: &SampleRow, now_nanos: u64, limits: &Limits) -> Result<Vec<u8>, RefusedRow> {
    if in_range(row.timestamp_nanos, now_nanos, limits) {
        encode_row(row).and_then(|line| {
            if line.len() > limits.max_batch_bytes {
                Err(RefusedRow::RowTooLarge)
            } else {
                Ok(line)
            }
        })
    } else {
        Err(RefusedRow::TimestampOutOfRange)
    }
}


fn group_rows(rows: &[SampleRow], now_nanos: u64, limits: &Limits) -> (Groups, BTreeMap<RefusedRow, u64>) {
    let mut groups = Groups::new();
    let mut refused = BTreeMap::new();
    rows.iter().for_each(|row| match admit(row, now_nanos, limits) {
        Ok(line) => {
            let when = moment(row.timestamp_nanos);
            groups.entry((row.tenant.clone(), when.year, when.month)).or_default().push(line);
        }
        Err(reason) => refuse(&mut refused, reason),
    });
    (groups, refused)
}


/// Cuts rows into batches of one tenant and one UTC month, within the row and byte caps; refused rows are counted, never sent.
pub fn encode_rows(rows: &[SampleRow], limits: &Limits, now_nanos: u64) -> Result<Encoded, EncodeError> {
    if limits.max_batch_rows == 0 {
        Err(EncodeError::ZeroBatchRows)
    } else if limits.max_batch_bytes == 0 {
        Err(EncodeError::ZeroBatchBytes)
    } else {
        let (groups, refused) = group_rows(rows, now_nanos, limits);
        let start = Accumulator {
            batches: Vec::new(),
            body: Vec::new(),
            rows: 0,
        };
        let done = groups.values().fold(start, |accumulator, lines| {
            flush(lines.iter().fold(accumulator, |current, line| append(current, line, limits)))
        });
        Ok(Encoded {
            batches: done.batches,
            refused,
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
