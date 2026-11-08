use crate::app::{bounded_lines, BoundedLine};
use crate::error::SinkError;
use crate::model::{Identity, MAX_MESSAGE_BYTES_LIMIT};
use crate::proto::EventBatch;
use crate::types::{BoxError, EventSink, EventWriter, SyncFn};
use core_audit::log::owner_only;
use data_encoding::HEXLOWER;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};


/// The events file as a writer plus the `(identity, sequence)` pairs already in it, so a resent batch is stored once.
pub struct EventStore {
    pub writer: EventWriter,
    pub sync: SyncFn,
    pub seen: HashSet<(Identity, u64)>,
}


/// Reads `<tenant> <agent-id> <sequence> <hex>`; the payload is not read.
pub fn parse_line(text: &str, line: usize) -> Result<(Identity, u64), SinkError> {
    let mut fields = text.split(' ');
    match (fields.next(), fields.next(), fields.next().map(str::parse::<u64>)) {
        (Some(tenant), Some(agent_id), Some(Ok(sequence))) => Ok((
            Identity {
                tenant: tenant.to_owned(),
                agent_id: agent_id.to_owned(),
            },
            sequence,
        )),
        _ => Err(SinkError::Corrupt { line }),
    }
}


/// Hex characters per payload byte.
pub const HEX_PER_BYTE: usize = 2;


/// Room for `<tenant> <agent-id> <sequence> ` ahead of the hex payload.
pub const EVENT_LINE_OVERHEAD: usize = 256;


/// Longest line of the events file: the hex of a payload up to the highest message bound a setting allows, plus the identity and sequence.
pub const MAX_EVENT_LINE_BYTES: usize = HEX_PER_BYTE * MAX_MESSAGE_BYTES_LIMIT + EVENT_LINE_OVERHEAD;


/// An oversized line refuses the file (the error carries its number): this sink did not write it.
pub fn load_seen(reader: &mut dyn BufRead) -> Result<HashSet<(Identity, u64)>, SinkError> {
    bounded_lines(reader, MAX_EVENT_LINE_BYTES)
        .zip(1..)
        .try_fold(HashSet::new(), |mut seen, (line, number)| match line? {
            BoundedLine::Text(text) => {
                seen.insert(parse_line(&text, number)?);
                Ok(seen)
            }
            BoundedLine::Oversized => Err(SinkError::Corrupt { line: number }),
        })
}


/// Opens (creating, owner only) the events file and learns what it already holds, so deduplication survives a restart.
pub fn open_event_store(path: &Path) -> Result<EventStore, SinkError> {
    let file = owner_only(OpenOptions::new().read(true).append(true).create(true))
        .open(path)
        .map_err(|source| SinkError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let seen = load_seen(&mut BufReader::new(&file))?;
    let syncer = file.try_clone()?;
    Ok(EventStore {
        writer: Box::new(file),
        sync: Box::new(move || syncer.sync_all()),
        seen,
    })
}


/// Appends and syncs one line unless this `(identity, sequence)` is already stored; returns whether it wrote.
pub fn store_batch(store: &Mutex<EventStore>, identity: Identity, batch: &EventBatch) -> Result<bool, SinkError> {
    let mut guard = store.lock().unwrap_or_else(PoisonError::into_inner);
    let EventStore { writer, sync, seen } = &mut *guard;
    let key = (identity, batch.sequence);
    if seen.contains(&key) {
        Ok(false)
    } else {
        let line = format!("{} {} {} {}\n", key.0.tenant, key.0.agent_id, key.1, HEXLOWER.encode(&batch.ecs_json));
        writer.write_all(line.as_bytes())?;
        writer.flush()?;
        sync()?;
        seen.insert(key);
        Ok(true)
    }
}


/// The event sink of the server example: a batch is acknowledged once it is on disk.
pub fn file_sink(store: Arc<Mutex<EventStore>>) -> EventSink {
    Box::new(move |identity: Identity, batch: EventBatch| {
        let shared = Arc::clone(&store);
        Box::pin(async move { store_batch(&shared, identity, &batch).map(drop).map_err(BoxError::from) })
    })
}
