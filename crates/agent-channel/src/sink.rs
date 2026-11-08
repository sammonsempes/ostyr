use crate::error::SinkError;
use crate::model::Identity;
use crate::proto::EventBatch;
use crate::types::{BoxError, EventSink};
use core_audit::log::{owner_only, sync_file};
use data_encoding::HEXLOWER;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};


/// The events file as a writer plus the `(identity, sequence)` pairs already in it, so a resent batch is stored once.
pub struct EventStore<Output> {
    pub writer: Output,
    pub sync: fn(&mut Output) -> io::Result<()>,
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


pub fn load_seen(reader: impl BufRead) -> Result<HashSet<(Identity, u64)>, SinkError> {
    reader.lines().zip(1..).try_fold(HashSet::new(), |mut seen, (text, line)| {
        seen.insert(parse_line(&text?, line)?);
        Ok(seen)
    })
}


/// Opens (creating, owner only) the events file and learns what it already holds, so deduplication survives a restart.
pub fn open_event_store(path: &Path) -> Result<EventStore<File>, SinkError> {
    let file = owner_only(OpenOptions::new().read(true).append(true).create(true))
        .open(path)
        .map_err(|source| SinkError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let seen = load_seen(BufReader::new(&file))?;
    Ok(EventStore {
        writer: file,
        sync: sync_file,
        seen,
    })
}


/// Appends and syncs one line unless this `(identity, sequence)` is already stored; returns whether it wrote.
pub fn store_batch<Output: Write>(store: &Mutex<EventStore<Output>>, identity: Identity, batch: &EventBatch) -> Result<bool, SinkError> {
    let mut guard = store.lock().unwrap_or_else(PoisonError::into_inner);
    let EventStore { writer, sync, seen } = &mut *guard;
    let key = (identity, batch.sequence);
    if seen.contains(&key) {
        tracing::debug!(sequence = batch.sequence, "duplicate batch not stored again");
        Ok(false)
    } else {
        let line = format!("{} {} {} {}\n", key.0.tenant, key.0.agent_id, key.1, HEXLOWER.encode(&batch.ecs_json));
        writer.write_all(line.as_bytes())?;
        writer.flush()?;
        sync(writer)?;
        seen.insert(key);
        Ok(true)
    }
}


/// The event sink of the server example: a batch is acknowledged once it is on disk.
pub fn file_sink<Output: Write + Send + 'static>(store: Arc<Mutex<EventStore<Output>>>) -> EventSink {
    Box::new(move |identity: Identity, batch: EventBatch| {
        let shared = Arc::clone(&store);
        Box::pin(async move { store_batch(&shared, identity, &batch).map(drop).map_err(BoxError::from) })
    })
}
