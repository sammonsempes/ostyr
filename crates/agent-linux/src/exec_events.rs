use crate::spool::append_within;
use crate::types::{MonotonicFn, OffsetFn, SharedSource, SpoolLock};
use ebpf_probes::drain::{DrainReport, Drained, KernelDropped};
use ebpf_probes::record::ExecRecord;
use serde_json::json;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


/// The exec producer may keep at most `max_spool_bytes / EXEC_SPOOL_DIVISOR` pending, so its lines never take the headroom of the other producers.
pub const EXEC_SPOOL_DIVISOR: u64 = 8;


pub const STATUS_INTERVAL_SECONDS: u64 = 60;


pub const DATASET_EXEC: &str = "ostyr.exec";


pub const DATASET_STATUS: &str = "ostyr.exec_probe.status";


pub const NANOS_PER_SECOND: i128 = 1_000_000_000;


/// Where the exec producer writes and the clocks it reads.
#[derive(Clone, Debug)]
pub struct ExecSink {
    pub spool: PathBuf,
    pub sending: PathBuf,
    pub lock: SpoolLock,
    pub settings: SharedSource,
    pub offset: OffsetFn,
    pub monotonic: MonotonicFn,
}


/// What was lost since the last status event; the two counter faults are drain counts, kept apart from the sums.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Losses {
    pub limited: u64,
    pub kernel_dropped: u64,
    pub refused: u64,
    pub spool_full: u64,
    pub bad_time: u64,
    pub counter_unknown: u64,
    pub counter_went_down: u64,
}


/// What the delivery keeps between two drains.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Delivery {
    pub losses: Losses,
    pub last_status: Option<u64>,
}


/// Realtime minus monotonic nanoseconds, sampled once per drain.
pub fn system_offset() -> i128 {
    let monotonic = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let monotonic_ns = i128::from(monotonic.tv_sec) * NANOS_PER_SECOND + i128::from(monotonic.tv_nsec);
    OffsetDateTime::now_utc().unix_timestamp_nanos() - monotonic_ns
}


/// The byte bound of the exec producer for one settings snapshot.
pub fn exec_cap(max_spool_bytes: u64) -> u64 {
    max_spool_bytes / EXEC_SPOOL_DIVISOR
}


/// `@timestamp` of a record: none when the sum leaves RFC 3339's range.
pub fn timestamp_text(offset: i128, monotonic_ns: u64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp_nanos(offset.saturating_add(i128::from(monotonic_ns)))
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
}


/// One exec event; `process.name` is the exec'ing user's text (untrusted), the ids are the real uid and gid of the record in the initial pid namespace.
pub fn exec_line(record: &ExecRecord, timestamp: &str) -> String {
    json!({
        "@timestamp": timestamp,
        "event": {"kind": "event", "category": ["process"], "type": ["start"], "dataset": DATASET_EXEC},
        "process": {
            "pid": record.pid,
            "name": record.comm,
            "parent": {"pid": record.ppid},
            "real_user": {"id": record.uid.to_string()},
            "real_group": {"id": record.gid.to_string()},
        },
    })
    .to_string()
}


/// The lines of a drain and the count of records refused for an unwritable time.
pub fn exec_lines(records: &[ExecRecord], offset: i128) -> (Vec<String>, u64) {
    let lines: Vec<String> = records
        .iter()
        .filter_map(|record| timestamp_text(offset, record.monotonic_ns).map(|stamp| exec_line(record, &stamp)))
        .collect();
    let refused = u64::try_from(records.len().saturating_sub(lines.len())).unwrap_or(u64::MAX);
    (lines, refused)
}


/// Adds one drain report to the pending losses.
pub fn add_report(losses: Losses, report: &DrainReport) -> Losses {
    let (dropped, unknown, went_down) = match report.kernel_dropped {
        KernelDropped::Counted(count) => (count, 0, 0),
        KernelDropped::Unknown => (0, 1, 0),
        KernelDropped::CounterWentDown => (0, 0, 1),
    };
    Losses {
        limited: losses.limited.saturating_add(report.limited),
        kernel_dropped: losses.kernel_dropped.saturating_add(dropped),
        refused: losses.refused.saturating_add(report.refused),
        counter_unknown: losses.counter_unknown.saturating_add(unknown),
        counter_went_down: losses.counter_went_down.saturating_add(went_down),
        ..losses
    }
}


/// Whether the status event is due: losses pending and none sent within `STATUS_INTERVAL_SECONDS`.
pub fn status_due(losses: &Losses, last_status: Option<u64>, now: u64) -> bool {
    losses != &Losses::default() && last_status.is_none_or(|last| now.saturating_sub(last) >= STATUS_INTERVAL_SECONDS)
}


/// The status event: every count under its own name, the two counter faults never folded into `kernel_dropped`.
pub fn status_line(losses: &Losses) -> String {
    json!({
        "event": {"kind": "state", "category": ["process"], "type": ["info"], "dataset": DATASET_STATUS},
        "ostyr": {"exec_probe": {
            "limited": losses.limited,
            "kernel_dropped": losses.kernel_dropped,
            "refused": losses.refused,
            "spool_full": losses.spool_full,
            "bad_time": losses.bad_time,
            "counter_unknown": losses.counter_unknown,
            "counter_went_down": losses.counter_went_down,
        }},
    })
    .to_string()
}


/// The one extra warn text of a drain whose own losses (spool bound, time) are not in the loader's line.
pub fn own_loss_text(spool_full: u64, bad_time: u64) -> Option<String> {
    (spool_full > 0 || bad_time > 0).then(|| format!("exec producer lost events: spool_full={spool_full} bad_time={bad_time}"))
}


/// One drain: the event lines within the exec cap, then the status event when due (one line a minute, so it is held to the whole bound, never the exec cap: a producer at its cap must still be able to report it); a failing write is the error.
pub fn deliver(sink: &ExecSink, state: Delivery, drained: &Drained) -> io::Result<Delivery> {
    let (lines, bad_time) = exec_lines(&drained.records, (sink.offset)());
    let bound = sink.settings.load().max_spool_bytes;
    let cap = exec_cap(bound);
    let written = append_within(&sink.lock, &sink.spool, &sink.sending, cap, &lines)?;
    let spool_full = if written { 0 } else { lines.len() as u64 };
    let pending = Losses {
        spool_full: state.losses.spool_full.saturating_add(spool_full),
        bad_time: state.losses.bad_time.saturating_add(bad_time),
        ..add_report(state.losses, &drained.report)
    };
    let now = (sink.monotonic)();
    let status = [status_line(&pending)];
    let sent = status_due(&pending, state.last_status, now) && append_within(&sink.lock, &sink.spool, &sink.sending, bound, &status)?;
    own_loss_text(spool_full, bad_time).iter().for_each(|text| tracing::warn!("{text}"));
    Ok(if sent {
        Delivery {
            losses: Losses::default(),
            last_status: Some(now),
        }
    } else {
        Delivery {
            losses: pending,
            last_status: state.last_status,
        }
    })
}


/// `deliver` for the probe thread: a failing write sets `stop` and reports the error to the controller, and the state is kept.
pub fn deliver_or_stop(sink: &ExecSink, state: Delivery, drained: &Drained, stop: &AtomicBool, failures: &Sender<io::Error>) -> Delivery {
    deliver(sink, state.clone(), drained).unwrap_or_else(|error| {
        tracing::error!(%error, "exec spool write failed, the probe stops");
        stop.store(true, Ordering::Relaxed);
        failures.send(error).inspect_err(|_| tracing::warn!("the controller is gone")).ok();
        state
    })
}
