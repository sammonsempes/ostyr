use crate::dirfs::{open_read, write_text_atomic};
use crate::error::{FlowFrameError, ForwardError};
use crate::event::flow_events;
use crate::flow_frame::{decode_flow_frame, single_flow_batch};
use crate::forward_model::{
    EventLines, ForwardLimits, ForwardReport, CURSOR_FILE, CURSOR_MAX_BYTES, CURSOR_TEMPORARY, FACILITY_NAMES, MAX_FORWARD_BATCH_RECORDS,
    MAX_FORWARD_HOST_BYTES, MAX_FORWARD_MESSAGE_BYTES, MAX_RAW_HOST_BYTES, MODULE, UNKNOWN_FACILITY,
};
use crate::listen_model::ListenerKind;
use crate::model::{SyslogRecord, FACILITY_WEIGHT, MAX_APP_BYTES};
use crate::parse::parse_syslog;
use crate::spool::{acknowledge, read_from};
use crate::spool_model::{Record, Spool};
use crate::types::{CursorWriter, DirHandle, SyncFn};
use agent_channel::spool::{append_back, suffixed, SENDING_SUFFIX};
use core_export::ecs::{blank_event, to_json, EcsEvent, EventFields, HostFields};
use core_export::types::LabelMap;
use ecs_normalise::suricata::is_unsafe;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use time::OffsetDateTime;


/// The next sequence to forward; a missing file is the start, a cursor file that is not a number is refused.
pub fn read_cursor(dir: &DirHandle) -> Result<u64, ForwardError> {
    match open_read(dir, CURSOR_FILE) {
        Ok(file) => {
            let mut text = String::new();
            file.take(CURSOR_MAX_BYTES).read_to_string(&mut text)?;
            Ok(text.trim().parse()?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}


/// Written to a temporary file in the spool directory, synced, renamed over the cursor, directory synced.
pub fn write_cursor(dir: &DirHandle, next: u64) -> io::Result<()> {
    write_text_atomic(dir, CURSOR_TEMPORARY, CURSOR_FILE, &format!("{next}\n"))
}


/// The size of a file, zero when it does not exist.
pub fn file_bytes(path: &Path) -> io::Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}


/// The text cut to at most `max` bytes on a character boundary, with a visible marker holding the number of bytes cut.
pub fn cut_text(text: &str, max: usize) -> String {
    let kept: String = text
        .chars()
        .scan(0usize, |used, character| {
            *used += character.len_utf8();
            (*used <= max).then_some(character)
        })
        .collect();
    if kept.len() < text.len() {
        format!("{kept}[+{} bytes cut]", text.len() - kept.len())
    } else {
        kept
    }
}


/// Characters the ecs-normalise classifier calls unsafe removed, then cut.
pub fn clean_text(text: &str, max: usize) -> String {
    cut_text(&text.chars().filter(|character| !is_unsafe(*character)).collect::<String>(), max)
}


/// Letters, digits, dot, dash, underscore and colon, never starting with a dash, within the host name limit.
pub fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_FORWARD_HOST_BYTES
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}


pub fn facility_name(priority: u8) -> &'static str {
    FACILITY_NAMES
        .get(usize::from(priority / FACILITY_WEIGHT))
        .copied()
        .unwrap_or(UNKNOWN_FACILITY)
}


const YEAR_ZERO_UNIX_SECONDS: i64 = -62_167_219_200;


/// The time of a unix second count when it is a year 0 to 9999 time that JSON can encode.
pub fn representable_time(seconds: i64) -> Option<OffsetDateTime> {
    Some(seconds)
        .filter(|value| *value >= YEAR_ZERO_UNIX_SECONDS)
        .and_then(|value| OffsetDateTime::from_unix_timestamp(value).ok())
}


/// The record time, or the forward time when the record has none or an unrepresentable one; never logs, the caller counts.
pub fn event_time(timestamp: Option<i64>, now: OffsetDateTime) -> OffsetDateTime {
    timestamp.and_then(representable_time).unwrap_or(now)
}


/// True when the record carries a time that cannot be represented, so `event_time` replaces it.
pub fn time_out_of_range(timestamp: Option<i64>) -> bool {
    timestamp.is_some_and(|seconds| representable_time(seconds).is_none())
}


pub fn build_event(sequence: u64, epoch: &str, parsed: &SyslogRecord, now: OffsetDateTime) -> EcsEvent {
    let facility = facility_name(parsed.priority);
    let valid_host = parsed.host.as_deref().filter(|host| valid_hostname(host));
    let raw_host = parsed.host.as_deref().filter(|host| !valid_hostname(host));
    let labels: LabelMap = [
        Some(("syslog_facility", facility.to_owned())),
        Some(("syslog_severity", (parsed.priority % FACILITY_WEIGHT).to_string())),
        Some(("collector_sequence", sequence.to_string())),
        Some(("collector_epoch", epoch.to_owned())),
        parsed.app.as_deref().map(|app| ("syslog_app", clean_text(app, MAX_APP_BYTES))),
        raw_host.map(|host| ("syslog_host_raw", clean_text(host, MAX_RAW_HOST_BYTES))),
        parsed.host.as_ref().map(|_| ("syslog_host_claimed", "true".to_owned())),
    ]
    .into_iter()
    .flatten()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_owned()),
            module: Some(MODULE.to_owned()),
            dataset: Some(format!("{MODULE}.{facility}")),
            severity: Some(u32::from(parsed.priority % FACILITY_WEIGHT)),
            ..EventFields::default()
        },
        message: Some(clean_text(&parsed.message, MAX_FORWARD_MESSAGE_BYTES)),
        host: valid_host.map(|host| HostFields {
            name: Some(host.to_owned()),
            ..HostFields::default()
        }),
        labels,
        ..blank_event(event_time(parsed.timestamp, now))
    }
}


/// The number of record times replaced in a batch, logged once when above zero (never per record).
pub fn report_time_substitutions(produced: &[EventLines]) -> u64 {
    let time_substituted = produced.iter().map(|event| event.time_substituted).sum::<u64>();
    if time_substituted > 0 {
        tracing::warn!(time_substituted, "record times out of range, the forward time is used");
    }
    time_substituted
}


/// The event lines of a spooled record by listener kind: one for a syslog message or a flow frame, an error when the payload is not that kind's.
pub fn event_line(record: &Record, kind: ListenerKind, epoch: &str, now: OffsetDateTime) -> Result<EventLines, ForwardError> {
    match kind {
        ListenerKind::Syslog => {
            let parsed = parse_syslog(&record.payload, now.year())?;
            Ok(EventLines {
                lines: vec![to_json(&build_event(record.sequence, epoch, &parsed, now))?],
                time_substituted: u64::from(time_out_of_range(parsed.timestamp)),
            })
        }
        ListenerKind::Netflow => {
            let (exporter, flow) = decode_flow_frame(&record.payload)?;
            let batch = single_flow_batch(flow);
            let lines = flow_events(&batch, exporter, epoch, record.sequence, now)
                .iter()
                .map(to_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(EventLines { lines, time_substituted: 0 })
        }
    }
}


/// A fixed reduction of an error for the log: never a value quoted from a frame.
pub fn forward_error_kind(error: &ForwardError) -> String {
    match error {
        ForwardError::Frame(FlowFrameError::Json(source)) => format!(
            "the flow frame is not a strict flow record ({:?}, line {}, column {})",
            source.classify(),
            source.line(),
            source.column()
        ),
        ForwardError::Frame(inner) => inner.to_string(),
        other => other.to_string(),
    }
}


pub fn is_unknown_version(error: &ForwardError) -> bool {
    matches!(error, ForwardError::Frame(FlowFrameError::UnknownVersion(_)))
}


/// Reads the records after the cursor, syncs the segments and directory holding them (once, only for a non-empty batch) so every forwarded sequence is durable, appends their event lines to the agent spool in one call, then moves the cursor and acknowledges. A record that does not decode is counted, logged once for the batch, and the cursor moves past it.
pub fn forward_batch(
    spool: &mut Spool,
    agent_spool: &Path,
    limits: &ForwardLimits,
    now: OffsetDateTime,
    write_cursor_to: CursorWriter,
    sync_to: SyncFn,
    cursor: u64,
) -> Result<ForwardReport, ForwardError> {
    let records = read_from(spool, cursor, limits.max_records.min(MAX_FORWARD_BATCH_RECORDS))?;
    let outcomes = records
        .iter()
        .map(|record| event_line(record, limits.kind, &spool.epoch, now).map_err(|error| (record.sequence, error)))
        .collect::<Vec<_>>();
    let failures = outcomes.iter().filter_map(|outcome| outcome.as_ref().err()).collect::<Vec<_>>();
    let unknown_version = failures.iter().filter(|(_, error)| is_unknown_version(error)).count() as u64;
    let malformed = failures.len() as u64 - unknown_version;
    let first_failure = failures
        .first()
        .map(|(sequence, error)| format!("sequence {sequence}: {}", forward_error_kind(error)));
    if let Some(first) = first_failure {
        tracing::warn!(malformed, unknown_version, %first, "spooled records skipped");
    }
    let produced = outcomes.into_iter().flatten().collect::<Vec<_>>();
    let time_substituted = report_time_substitutions(&produced);
    let lines = produced.into_iter().flat_map(|event| event.lines).collect::<Vec<_>>();
    let forwarded = lines.len() as u64;
    if let Some(last) = records.last().map(|record| record.sequence) {
        sync_to(spool, cursor, last.saturating_add(1))?;
    }
    append_back(lines.into_iter().map(Ok), agent_spool)?;
    if let Some(last) = records.last().map(|record| record.sequence) {
        write_cursor_to(&spool.dir, last.saturating_add(1))?;
        acknowledge(spool, last)?;
    }
    Ok(ForwardReport {
        forwarded,
        skipped_unparsable: malformed,
        skipped_unknown_version: unknown_version,
        refused_full: 0,
        time_substituted,
    })
}


/// One forward pass. At least once: a failure between the append and the cursor write forwards the same batch again with the same `collector_sequence`.
pub fn forward_once(
    spool: &mut Spool,
    agent_spool: &Path,
    limits: &ForwardLimits,
    now: OffsetDateTime,
    write_cursor_to: CursorWriter,
    sync_to: SyncFn,
) -> Result<ForwardReport, ForwardError> {
    let cursor = read_cursor(&spool.dir)?.min(spool.next_sequence);
    let pending = file_bytes(agent_spool)?.saturating_add(file_bytes(&suffixed(agent_spool, SENDING_SUFFIX))?);
    if pending >= limits.agent_spool_max_bytes {
        tracing::warn!(pending, "the agent spool is full, the batch is not forwarded and the cursor stays");
        Ok(ForwardReport {
            refused_full: 1,
            ..ForwardReport::default()
        })
    } else {
        forward_batch(spool, agent_spool, limits, now, write_cursor_to, sync_to, cursor)
    }
}
