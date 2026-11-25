//! Decisions of one drain of the exec ring: decode, refuse, rate limit, count and report.

use crate::limiter::{admit, take_dropped, Limiter, MAX_EXEC_EVENTS_PER_SECOND, MAX_FILE_EVENTS_PER_SECOND};
use crate::record::{decode_exec, decode_file, exec_time, file_time, ExecRecord, FileRecord};
use crate::types::{DecodeFn, TimeFn};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;


pub const MAX_DRAIN_PER_POLL: usize = 2048;


pub const POLL_INTERVAL_MILLIS: u64 = 250;


pub const REASON_UNKNOWN: &str = "kernel_dropped_unknown";


pub const REASON_WENT_DOWN: &str = "counter_went_down";


#[derive(Clone, Copy, Debug)]
pub struct Decoder<Item> {
    pub decode: DecodeFn<Item>,
    pub time_of: TimeFn<Item>,
    pub per_second: u32,
}


pub const EXEC_DECODER: Decoder<ExecRecord> = Decoder {
    decode: decode_exec,
    time_of: exec_time,
    per_second: MAX_EXEC_EVENTS_PER_SECOND,
};


pub const FILE_DECODER: Decoder<FileRecord> = Decoder {
    decode: decode_file,
    time_of: file_time,
    per_second: MAX_FILE_EVENTS_PER_SECOND,
};


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch<Item = ExecRecord> {
    pub records: Vec<Item>,
    pub read: usize,
    pub refused: u64,
    pub first_refused_len: Option<usize>,
    pub limited: u64,
}


impl<Item> Default for Batch<Item> {
    fn default() -> Self {
        Batch {
            records: Vec::new(),
            read: 0,
            refused: 0,
            first_refused_len: None,
            limited: 0,
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelDropped {
    Counted(u64),
    Unknown,
    CounterWentDown,
}


impl fmt::Display for KernelDropped {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelDropped::Counted(count) => write!(formatter, "{count}"),
            KernelDropped::Unknown => write!(formatter, "{REASON_UNKNOWN}"),
            KernelDropped::CounterWentDown => write!(formatter, "{REASON_WENT_DOWN}"),
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainReport {
    pub delivered: usize,
    pub refused: u64,
    pub first_refused_len: Option<usize>,
    pub limited: u64,
    pub kernel_dropped: KernelDropped,
    pub more_pending: bool,
}


/// Sums the per-CPU values of the drop counter; a sum past `u64::MAX` stays there.
pub fn sum_per_cpu(values: &[u64]) -> u64 {
    values.iter().fold(0, |sum: u64, value| sum.saturating_add(*value))
}


/// Whether the probe may go on to attach: false once `stop` is set (a disable seen during a slow load).
pub fn may_proceed(stop: &AtomicBool) -> bool {
    !stop.load(Ordering::Relaxed)
}


/// Reads at most `max_records` raw records, decodes each with `decoder` (a refused one is counted with its length only) and rate limits by the record's own kernel time and the decoder's own budget.
pub fn decode_batch<Item>(raw: &mut dyn Iterator<Item = Vec<u8>>, limiter: &mut Limiter, max_records: usize, decoder: &Decoder<Item>) -> Batch<Item> {
    let mut batch = raw.take(max_records).fold(Batch::default(), |mut batch, bytes| {
        batch.read = batch.read.saturating_add(1);
        match (decoder.decode)(&bytes) {
            Err(_) => {
                batch.refused = batch.refused.saturating_add(1);
                batch.first_refused_len = batch.first_refused_len.or(Some(bytes.len()));
            }
            Ok(record) => {
                if admit(limiter, (decoder.time_of)(&record), decoder.per_second) {
                    batch.records.push(record);
                }
            }
        }
        batch
    });
    batch.limited = take_dropped(limiter);
    batch
}


/// Turns the kernel counter into a delta against the baseline kept by the probe: an unreadable counter is `Unknown`, a lower value is `CounterWentDown` and becomes the baseline.
pub fn kernel_dropped(baseline: &mut u64, current: Option<u64>) -> KernelDropped {
    match current {
        None => KernelDropped::Unknown,
        Some(value) if value < *baseline => {
            *baseline = value;
            KernelDropped::CounterWentDown
        }
        Some(value) => {
            let delta = value.saturating_sub(*baseline);
            *baseline = value;
            KernelDropped::Counted(delta)
        }
    }
}


/// Builds the report; `more_pending` is only information, the caller never polls again at once.
pub fn report_of<Item>(batch: &Batch<Item>, max_records: usize, kernel: KernelDropped) -> DrainReport {
    DrainReport {
        delivered: batch.records.len(),
        refused: batch.refused,
        first_refused_len: batch.first_refused_len,
        limited: batch.limited,
        kernel_dropped: kernel,
        more_pending: batch.read >= max_records,
    }
}


/// One line of counts for the probe `name` when anything was lost, refused or unknown.
pub fn warning_text(name: &str, report: &DrainReport) -> Option<String> {
    let kernel_lost = report.kernel_dropped != KernelDropped::Counted(0);
    let lossy = report.limited > 0 || report.refused > 0 || kernel_lost;
    let first_refused = report.first_refused_len.map_or_else(|| "none".to_string(), |length| length.to_string());
    lossy.then(|| {
        format!(
            "{} drain lost events: delivered={} refused={} first_refused_len={} limited={} kernel_dropped={} more_pending={}",
            name, report.delivered, report.refused, first_refused, report.limited, report.kernel_dropped, report.more_pending
        )
    })
}


/// The wait before the next poll: always the fixed interval, whatever `more_pending` says (the overflow stays in the kernel drop counter).
pub fn wait_after(_report: &DrainReport) -> Duration {
    Duration::from_millis(POLL_INTERVAL_MILLIS)
}


#[derive(Clone, Debug)]
pub struct Drained<Item = ExecRecord> {
    pub records: Vec<Item>,
    pub report: DrainReport,
}


/// Finishes one drain: the delta against the baseline, the report and the single warn text (none when nothing was lost, refused or unknown).
pub fn finish_drain<Item>(
    name: &str,
    batch: Batch<Item>,
    max_records: usize,
    baseline: &mut u64,
    current: Option<u64>,
) -> (Drained<Item>, Option<String>) {
    let kernel = kernel_dropped(baseline, current);
    let report = report_of(&batch, max_records, kernel);
    let warning = warning_text(name, &report);
    (
        Drained {
            records: batch.records,
            report,
        },
        warning,
    )
}


/// Polls at most `max_polls` times or until `stop` is set: one drain, one delivery, one fixed wait from `wait_after` per poll, and the count of polls done.
pub fn poll_loop(
    stop: &AtomicBool,
    max_polls: u32,
    drain: &mut dyn FnMut() -> Drained,
    deliver: &mut dyn FnMut(Drained),
    sleep: &mut dyn FnMut(Duration),
) -> u32 {
    let polls = (0..max_polls).take_while(|_| !stop.load(Ordering::Relaxed)).map(|_| {
        let drained = drain();
        let wait = wait_after(&drained.report);
        deliver(drained);
        sleep(wait);
    });
    u32::try_from(polls.count()).unwrap_or(u32::MAX)
}
