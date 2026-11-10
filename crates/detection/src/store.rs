use crate::error::SinkError;
use crate::model::{
    AlertRecord, AlertStore, FileStore, MAX_ALERTS_PER_BATCH, MAX_ALERT_LINE_BYTES, MAX_FIELD_CHARS, MAX_GROUP_FIELDS, MAX_STORED_EVENT_IDS,
};
use crate::types::{AlertSyncFn, AlertWriter, RotateFn};
use agent_channel::app::{bounded_lines, BoundedLine};
use core_audit::log::owner_only;
use std::collections::{BTreeMap, HashSet};
use std::fs::{remove_file, rename, File, OpenOptions};
use std::io::{self, BufRead, BufReader, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use tracing::warn;


pub const OMITTED_KEY: &str = "[omitted]";


/// The id of one stored line; a blank or torn line (an interrupted write) is skipped and logged, never an error.
pub fn line_id(text: &str, number: usize) -> Option<String> {
    if text.trim().is_empty() {
        None
    } else {
        serde_json::from_str::<AlertRecord>(text)
            .inspect_err(|_| warn!(line = number, "alerts file line skipped: not an alert (interrupted write)"))
            .ok()
            .map(|record| record.id)
    }
}


/// The ids already stored; a damaged or oversized line is skipped and logged, more than `max_ids` ids refuses the file.
pub fn load_seen(reader: &mut dyn BufRead, max_line: usize, max_ids: usize) -> Result<HashSet<String>, SinkError> {
    bounded_lines(reader, max_line)
        .zip(1..)
        .try_fold(HashSet::new(), |mut seen, (line, number)| match line {
            Ok(BoundedLine::Text(text)) => {
                line_id(&text, number).into_iter().for_each(|id| {
                    seen.insert(id);
                });
                if seen.len() > max_ids {
                    Err(SinkError::TooManyAlerts { max: max_ids })
                } else {
                    Ok(seen)
                }
            }
            Ok(BoundedLine::Oversized { .. }) => {
                warn!(line = number, "alerts file line skipped: over the line cap");
                Ok(seen)
            }
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                warn!(line = number, "alerts file line skipped: not UTF-8 (interrupted write)");
                Ok(seen)
            }
            Err(error) => Err(SinkError::Read(error)),
        })
}


/// `damaged` makes the next write start with a newline, so a torn last line can never swallow a record.
pub fn new_store(output: (AlertWriter, AlertSyncFn), rotate: RotateFn, seen: HashSet<String>, damaged: bool, max_stored: usize) -> AlertStore {
    let (writer, sync) = output;
    AlertStore {
        inner: Mutex::new(FileStore {
            writer,
            sync,
            rotate,
            seen,
            damaged,
            max_stored,
        }),
    }
}


pub fn open_file(path: &Path) -> io::Result<File> {
    owner_only(OpenOptions::new().read(true).append(true).create(true)).open(path)
}


pub fn output_of(file: File) -> io::Result<(AlertWriter, AlertSyncFn)> {
    let syncer = file.try_clone()?;
    let writer: AlertWriter = Box::new(file);
    let sync: AlertSyncFn = Box::new(move || syncer.sync_all());
    Ok((writer, sync))
}


pub fn rotated_name(path: &Path, number: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{number}"));
    PathBuf::from(name)
}


/// Renames `<file>` to `<file>.1`, `.1` to `.2` and so on; the file numbered `keep` is removed (logged) so at most `keep` rotated files remain.
pub fn rotate_files(path: &Path, keep: usize) -> io::Result<()> {
    let oldest = rotated_name(path, keep);
    if oldest.exists() {
        let file = oldest.display().to_string();
        warn!(file, "oldest rotated alerts file removed");
        remove_file(&oldest)?;
    }
    (1..keep).rev().try_for_each(|number| shift_rotated(path, number))?;
    rename(path, rotated_name(path, 1))
}


/// Moves `<file>.<number>` to the next number when it exists.
pub fn shift_rotated(path: &Path, number: usize) -> io::Result<()> {
    let from = rotated_name(path, number);
    if from.exists() {
        rename(&from, rotated_name(path, number + 1))
    } else {
        Ok(())
    }
}


/// Opens (creating, owner only) the alerts file and learns the ids it holds, so deduplication survives a restart; the file is rotated once it holds `max_stored` ids.
pub fn open_alert_store(path: &Path, max_stored: usize, keep: usize) -> Result<AlertStore, SinkError> {
    let file = open_file(path).map_err(|source| SinkError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    let id_cap = max_stored.saturating_add(MAX_ALERTS_PER_BATCH);
    let seen = load_seen(&mut BufReader::new(&file), MAX_ALERT_LINE_BYTES, id_cap)?;
    let damaged = file.metadata().map_err(SinkError::Read)?.len() > 0;
    let output = output_of(file).map_err(SinkError::Write)?;
    let owned = path.to_path_buf();
    let rotate: RotateFn = Box::new(move || {
        rotate_files(&owned, keep)?;
        open_file(&owned).and_then(output_of)
    });
    Ok(new_store(output, rotate, seen, damaged, max_stored))
}


/// `text` cut to `max` characters, with a marker that keeps the original length.
pub fn cut_text(text: &str, max: usize) -> String {
    let length = text.chars().count();
    if length <= max {
        text.to_owned()
    } else {
        format!("{}[cut, {length} chars]", text.chars().take(max).collect::<String>())
    }
}


/// The record as it is written: every copied field cut, at most `MAX_GROUP_FIELDS` group fields and `MAX_STORED_EVENT_IDS` event ids, each cut marked and counted; the id is kept.
pub fn bound_record(record: &AlertRecord) -> AlertRecord {
    let omitted_fields = record.group.len().saturating_sub(MAX_GROUP_FIELDS);
    let mut group: BTreeMap<String, String> = record
        .group
        .iter()
        .take(MAX_GROUP_FIELDS)
        .map(|(name, value)| (cut_text(name, MAX_FIELD_CHARS), cut_text(value, MAX_FIELD_CHARS)))
        .collect();
    if omitted_fields > 0 {
        group.insert(OMITTED_KEY.to_owned(), format!("{omitted_fields} more fields omitted"));
    }
    let omitted_ids = record.event_ids.len().saturating_sub(MAX_STORED_EVENT_IDS);
    let mut event_ids: Vec<String> = record
        .event_ids
        .iter()
        .take(MAX_STORED_EVENT_IDS)
        .map(|event_id| cut_text(event_id, MAX_FIELD_CHARS))
        .collect();
    if omitted_ids > 0 {
        event_ids.push(format!("[{omitted_ids} more event ids omitted]"));
    }
    AlertRecord {
        id: record.id.clone(),
        tenant: record.tenant.clone(),
        rule_id: cut_text(&record.rule_id, MAX_FIELD_CHARS),
        rule_title: cut_text(&record.rule_title, MAX_FIELD_CHARS),
        group,
        first_ms: record.first_ms,
        last_ms: record.last_ms,
        event_ids,
    }
}


/// Writes one bounded record as one line; after a failure the next line starts with a newline.
pub fn write_record(store: &mut FileStore, record: &AlertRecord) -> Result<(), SinkError> {
    let json = serde_json::to_string(&bound_record(record)).map_err(SinkError::Serialize)?;
    let line = if store.damaged { format!("\n{json}\n") } else { format!("{json}\n") };
    let outcome = store.writer.write_all(line.as_bytes()).and_then(|()| store.writer.flush());
    store.damaged = outcome.is_err();
    outcome.map_err(SinkError::Write)
}


/// A full file is renamed away and a new one started; the ids of the rotated file are forgotten, so a redelivery across a rotation may repeat one alert.
pub fn rotate_if_full(store: &mut FileStore) -> Result<(), SinkError> {
    if store.seen.len() >= store.max_stored {
        let (writer, sync) = (store.rotate)().map_err(SinkError::Rotate)?;
        let stored = store.seen.len();
        warn!(stored, "alerts file rotated");
        store.writer = writer;
        store.sync = sync;
        store.seen.clear();
        store.damaged = false;
    }
    Ok(())
}


/// Appends the records not stored yet, syncs, then remembers their ids (after a failed fsync the retry rewrites them); returns the new count.
pub fn file_commit(store: &AlertStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    let mut guard = store.inner.lock().unwrap_or_else(PoisonError::into_inner);
    let inner = &mut *guard;
    if records.iter().any(|record| record.tenant != tenant) {
        Err(SinkError::TenantMismatch)
    } else {
        rotate_if_full(inner)?;
        let fresh = records.iter().try_fold(HashSet::new(), |mut written: HashSet<String>, record| {
            if inner.seen.contains(&record.id) || written.contains(&record.id) {
                Ok(written)
            } else {
                write_record(inner, record).map(|()| {
                    written.insert(record.id.clone());
                    written
                })
            }
        })?;
        if !fresh.is_empty() {
            (inner.sync)().map_err(SinkError::Sync)?;
        }
        let count = fresh.len();
        inner.seen.extend(fresh);
        Ok(count)
    }
}
