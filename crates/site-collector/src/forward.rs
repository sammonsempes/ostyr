use crate::dirfs::{create_append, open_read, remove_named, rename_named, sync_directory};
use crate::error::ForwardError;
use crate::forward_model::{
    ForwardLimits, ForwardReport, BIDI_CONTROLS, CURSOR_FILE, CURSOR_MAX_BYTES, CURSOR_TEMPORARY, FACILITY_NAMES, MAX_FORWARD_BATCH_RECORDS,
    MAX_FORWARD_HOST_BYTES, MAX_FORWARD_MESSAGE_BYTES, MAX_RAW_HOST_BYTES, MODULE, UNKNOWN_FACILITY,
};
use crate::model::{SyslogRecord, FACILITY_WEIGHT, MAX_APP_BYTES};
use crate::parse::parse_syslog;
use crate::spool::{acknowledge, read_from};
use crate::spool_model::{Record, Spool};
use crate::types::{CursorWriter, DirHandle};
use agent_channel::spool::{append_back, suffixed, SENDING_SUFFIX};
use core_export::ecs::{blank_event, to_json, EcsEvent, EventFields, HostFields};
use core_export::types::LabelMap;
use std::fs;
use std::io::{self, Read, Write};
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


/// Written to a temporary file in the spool directory, synced, renamed over the cursor, directory synced: every step relative to the opened directory.
pub fn write_cursor(dir: &DirHandle, next: u64) -> io::Result<()> {
    match remove_named(dir, CURSOR_TEMPORARY) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        Ok(()) | Err(_) => Ok(()),
    }?;
    let mut file = create_append(dir, CURSOR_TEMPORARY)?;
    writeln!(file, "{next}")?;
    file.sync_all()?;
    rename_named(dir, CURSOR_TEMPORARY, CURSOR_FILE)?;
    sync_directory(dir)
}


/// The size of a file, zero when it does not exist.
pub fn file_bytes(path: &Path) -> io::Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}


pub fn is_unsafe_char(character: char) -> bool {
    character.is_control() || BIDI_CONTROLS.contains(&character)
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


/// Control and bidirectional characters removed, then cut.
pub fn clean_text(text: &str, max: usize) -> String {
    cut_text(&text.chars().filter(|character| !is_unsafe_char(*character)).collect::<String>(), max)
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


/// The record time, or the forward time when the record has none or an unrepresentable one.
pub fn event_time(timestamp: Option<i64>, now: OffsetDateTime) -> OffsetDateTime {
    match timestamp.map(OffsetDateTime::from_unix_timestamp) {
        Some(Ok(time)) => time,
        Some(Err(error)) => {
            tracing::warn!(%error, "record time out of range, the forward time is used");
            now
        }
        None => now,
    }
}


pub fn build_event(sequence: u64, parsed: &SyslogRecord, now: OffsetDateTime) -> EcsEvent {
    let facility = facility_name(parsed.priority);
    let valid_host = parsed.host.as_deref().filter(|host| valid_hostname(host));
    let raw_host = parsed.host.as_deref().filter(|host| !valid_hostname(host));
    let labels: LabelMap = [
        Some(("syslog_facility", facility.to_owned())),
        Some(("syslog_severity", (parsed.priority % FACILITY_WEIGHT).to_string())),
        Some(("collector_sequence", sequence.to_string())),
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


/// The JSON line of a spooled record, or none when it no longer parses or encodes (logged with the sequence and the error, never the payload).
pub fn event_line(record: &Record, now: OffsetDateTime) -> Option<String> {
    let line = parse_syslog(&record.payload, now.year())
        .map_err(ForwardError::from)
        .and_then(|parsed| to_json(&build_event(record.sequence, &parsed, now)).map_err(ForwardError::from));
    line.map_err(|error| tracing::warn!(sequence = record.sequence, %error, "spooled record skipped"))
        .ok()
}


/// Reads the records after the cursor, appends their event lines to the agent spool in one call, then moves the cursor and acknowledges.
pub fn forward_batch(
    spool: &mut Spool,
    agent_spool: &Path,
    max_records: usize,
    now: OffsetDateTime,
    write_cursor_to: CursorWriter,
    cursor: u64,
) -> Result<ForwardReport, ForwardError> {
    let records = read_from(spool, cursor, max_records.min(MAX_FORWARD_BATCH_RECORDS))?;
    let lines = records.iter().map(|record| event_line(record, now)).collect::<Vec<_>>();
    let forwarded = lines.iter().flatten().count() as u64;
    append_back(lines.into_iter().flatten().map(Ok), agent_spool)?;
    if let Some(last) = records.last().map(|record| record.sequence) {
        write_cursor_to(&spool.dir, last.saturating_add(1))?;
        acknowledge(spool, last)?;
    }
    Ok(ForwardReport {
        forwarded,
        skipped_unparsable: records.len() as u64 - forwarded,
        refused_full: 0,
    })
}


/// One forward pass. At least once: a failure between the append and the cursor write forwards the same batch again with the same `collector_sequence`.
pub fn forward_once(
    spool: &mut Spool,
    agent_spool: &Path,
    limits: &ForwardLimits,
    now: OffsetDateTime,
    write_cursor_to: CursorWriter,
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
        forward_batch(spool, agent_spool, limits.max_records, now, write_cursor_to, cursor)
    }
}
