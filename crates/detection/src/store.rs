use crate::error::SinkError;
use crate::model::{AlertRecord, AlertStore, FileStore, MAX_ALERT_LINE_BYTES, MAX_STORED_ALERTS};
use crate::types::{AlertSyncFn, AlertWriter};
use agent_channel::app::{bounded_lines, BoundedLine};
use core_audit::log::owner_only;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use tracing::warn;


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


/// The ids already stored; a line over `max_line` bytes or more than `max_ids` ids refuses the file.
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
            Ok(BoundedLine::Oversized { .. }) => Err(SinkError::LineTooLong { line: number }),
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                warn!(line = number, "alerts file line skipped: not UTF-8 (interrupted write)");
                Ok(seen)
            }
            Err(error) => Err(SinkError::Read(error)),
        })
}


/// `damaged` makes the next write start with a newline, so a torn last line can never swallow a record.
pub fn new_store(writer: AlertWriter, sync: AlertSyncFn, seen: HashSet<String>, damaged: bool) -> AlertStore {
    AlertStore {
        inner: Mutex::new(FileStore {
            writer,
            sync,
            seen,
            damaged,
            unsynced: false,
        }),
    }
}


/// Opens (creating, owner only) the alerts file and learns the ids it holds, so deduplication survives a restart.
pub fn open_alert_store(path: &Path) -> Result<AlertStore, SinkError> {
    let file = owner_only(OpenOptions::new().read(true).append(true).create(true))
        .open(path)
        .map_err(|source| SinkError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let seen = load_seen(&mut BufReader::new(&file), MAX_ALERT_LINE_BYTES, MAX_STORED_ALERTS)?;
    let damaged = file.metadata().map_err(SinkError::Read)?.len() > 0;
    let syncer = file.try_clone().map_err(SinkError::Write)?;
    Ok(new_store(Box::new(file), Box::new(move || syncer.sync_all()), seen, damaged))
}


/// Writes one record as one line; after a failure the next line starts with a newline.
pub fn write_record(store: &mut FileStore, record: &AlertRecord) -> Result<(), SinkError> {
    let json = serde_json::to_string(record).map_err(SinkError::Serialize)?;
    let line = if store.damaged { format!("\n{json}\n") } else { format!("{json}\n") };
    let outcome = store.writer.write_all(line.as_bytes()).and_then(|()| store.writer.flush());
    store.damaged = outcome.is_err();
    outcome.map_err(SinkError::Write)?;
    store.unsynced = true;
    store.seen.insert(record.id.clone());
    Ok(())
}


/// Appends the records whose id is not stored yet, one line each, then syncs; returns how many were new. `Ok` means every record is on disk.
pub fn file_commit(store: &AlertStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    let mut guard = store.inner.lock().unwrap_or_else(PoisonError::into_inner);
    let inner = &mut *guard;
    if records.iter().any(|record| record.tenant != tenant) {
        Err(SinkError::TenantMismatch)
    } else {
        let fresh = records.iter().try_fold(0, |count: usize, record| {
            if inner.seen.contains(&record.id) {
                Ok(count)
            } else {
                write_record(inner, record).map(|()| count + 1)
            }
        })?;
        if fresh > 0 || inner.unsynced {
            (inner.sync)().map_err(SinkError::Sync)?;
            inner.unsynced = false;
        }
        Ok(fresh)
    }
}
