use crate::error::{HeaderError, KeaError, RowError};
use crate::header::{parse_header, Columns};
use crate::row::{convert_row, Converted};
use crate::types::{FileIdentity, LeaseKey, MalformedCounts, SeenLeases};
use core_export::ecs::EcsEvent;
use ecs_normalise::stream::{read_raw_line, RawLine};
use std::collections::VecDeque;
#[cfg(not(unix))]
use std::fs::symlink_metadata;
use std::fs::{File, Metadata};
use std::io::{self, BufReader, Seek, SeekFrom};
use std::iter::from_fn;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};


const COLUMN_COUNT_KIND: &str = "column-count";


pub const MAX_LINE_BYTES: u64 = 65_536;


pub const MAX_SEEN_LEASES: usize = 100_000;


pub const MAX_LINES_PER_POLL: usize = 10_000;


pub const MAX_OPEN_HANDLES: usize = 8;


const COMPACTED_SUFFIX: &str = ".2";


/// The bounds of one reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_line: u64,
    pub max_seen: usize,
    pub max_lines: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line: MAX_LINE_BYTES,
            max_seen: MAX_SEEN_LEASES,
            max_lines: MAX_LINES_PER_POLL,
        }
    }
}


/// Where the reader stands in the file: its handle and identity, the offset of the next unread line and the columns read from the header.
#[derive(Debug, Default)]
pub struct FollowState {
    pub open: Option<File>,
    pub identity: Option<FileIdentity>,
    pub offset: u64,
    pub columns: Option<Columns>,
    pub seen: SeenLeases,
    pub queued: VecDeque<Queued>,
    pub compacted: Option<Compacted>,
    pub missing_counted: bool,
}


/// The compacted file being read: its handle, identity and offset persist across polls until its end.
#[derive(Debug)]
pub struct Compacted {
    pub file: File,
    pub identity: FileIdentity,
    pub offset: u64,
    pub columns: Option<Columns>,
    pub floor: Option<i64>,
    pub emit: bool,
    pub done: bool,
}


/// A newer file seen while the current one was still draining; it is read from its header once the current one is drained.
#[derive(Debug)]
pub struct Queued {
    pub file: File,
    pub identity: FileIdentity,
}


#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts {
    pub processed: u64,
    pub duplicate: u64,
    pub evicted: u64,
    pub restarts: u64,
    pub absent: u64,
    pub refused: u64,
    pub recovered: u64,
    pub unrecovered: u64,
    pub malformed: MalformedCounts,
}


#[cfg(unix)]
pub fn identity(metadata: &Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}


#[cfg(not(unix))]
pub fn identity(_metadata: &Metadata) -> FileIdentity {
    (0, 0)
}


#[cfg(unix)]
fn open_handle(path: &Path) -> Result<Option<(File, Metadata)>, KeaError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY)
        .open(path)
    {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => Err(KeaError::NotRegular),
        Err(error) => Err(KeaError::Io(error)),
        Ok(file) => {
            let metadata = file.metadata()?;
            Ok(Some((file, metadata)))
        }
    }
}


#[cfg(not(unix))]
fn open_handle(path: &Path) -> Result<Option<(File, Metadata)>, KeaError> {
    match symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(KeaError::Io(error)),
        Ok(linked) if !linked.file_type().is_file() => Err(KeaError::NotRegular),
        Ok(_) => {
            let file = File::open(path)?;
            let metadata = file.metadata()?;
            Ok(Some((file, metadata)))
        }
    }
}


fn open_regular(path: &Path) -> Result<Option<(File, FileIdentity, u64)>, KeaError> {
    match open_handle(path)? {
        None => Ok(None),
        Some((file, metadata)) if metadata.is_file() => Ok(Some((file, identity(&metadata), metadata.len()))),
        Some(_) => Err(KeaError::NotRegular),
    }
}


fn complete(raw: &RawLine, start: u64, end: u64) -> bool {
    match raw {
        RawLine::Text(bytes) => end - start > bytes.len() as u64,
        RawLine::TooLong => true,
    }
}


fn next_line(reader: &mut BufReader<&File>, max_line: u64) -> io::Result<Option<(RawLine, u64)>> {
    let start = reader.stream_position()?;
    match read_raw_line(reader, max_line)? {
        None => Ok(None),
        Some(raw) => {
            let end = reader.stream_position()?;
            Ok(complete(&raw, start, end).then_some((raw, end)))
        }
    }
}


fn header_text(raw: RawLine) -> Result<Columns, HeaderError> {
    match raw {
        RawLine::TooLong => Err(HeaderError::TooLong),
        RawLine::Text(bytes) => parse_header(std::str::from_utf8(&bytes)?),
    }
}


fn row_text(raw: RawLine) -> Result<String, RowError> {
    match raw {
        RawLine::TooLong => Err(RowError::TooLong),
        RawLine::Text(bytes) => String::from_utf8(bytes).map_err(|_| RowError::Utf8),
    }
}


/// Records a lease key; true when it is new. The smallest key is evicted past `max_seen` and the eviction counted.
pub fn remember(seen: &mut SeenLeases, key: LeaseKey, max_seen: usize, counts: &mut Counts) -> bool {
    let fresh = seen.insert(key);
    if seen.len() > max_seen {
        counts.evicted += u64::from(seen.pop_first().is_some());
    }
    fresh
}


fn count_malformed(counts: &mut Counts, error: &RowError) {
    let kind = error.to_string();
    let slot = counts.malformed.entry(kind.clone()).or_insert(0);
    let first = *slot == 0;
    *slot += 1;
    if first {
        warn!(kind, "lease row refused, further rows of this kind are only counted");
    }
}


fn handle_row(columns: &Columns, state_seen: &mut SeenLeases, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>, raw: RawLine) {
    match row_text(raw).and_then(|text| convert_row(columns, &text)) {
        Ok(Converted { event, key }) => {
            if remember(state_seen, key, limits.max_seen, counts) {
                out.push(event);
                counts.processed += 1;
            } else {
                counts.duplicate += 1;
            }
        }
        Err(error) => count_malformed(counts, &error),
    }
}


fn handle_line(state: &mut FollowState, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>, raw: RawLine) -> Result<(), KeaError> {
    match state.columns.as_ref() {
        None => {
            let columns = header_text(raw)?;
            state.columns = Some(columns);
        }
        Some(columns) => handle_row(columns, &mut state.seen, limits, counts, out, raw),
    }
    Ok(())
}


fn read_lines(file: &File, state: &mut FollowState, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>) -> Result<usize, KeaError> {
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(state.offset))?;
    from_fn(|| next_line(&mut reader, limits.max_line).transpose())
        .take(limits.max_lines)
        .try_fold(0, |lines, item| {
            let (raw, end) = item?;
            handle_line(state, limits, counts, out, raw)?;
            state.offset = end;
            Ok::<usize, KeaError>(lines + 1)
        })
}


/// The path as it was opened: the handle, its identity and its length.
#[derive(Debug)]
pub struct Opened {
    pub file: File,
    pub identity: FileIdentity,
    pub length: u64,
}


fn newest_identity(state: &FollowState) -> Option<FileIdentity> {
    state.queued.back().map(|queued| queued.identity).or(state.identity)
}


fn queue_new(opened: Opened, state: &mut FollowState) {
    if state.queued.len() < MAX_OPEN_HANDLES {
        state.queued.push_back(Queued {
            file: opened.file,
            identity: opened.identity,
        });
    }
}


fn register(opened: Opened, state: &mut FollowState, counts: &mut Counts) -> File {
    match (state.open.take(), newest_identity(state)) {
        (Some(current), Some(newest)) if newest == opened.identity => {
            if state.queued.is_empty() && opened.length < state.offset {
                counts.restarts += 1;
                state.offset = 0;
                state.columns = None;
            }
            current
        }
        (Some(current), Some(_)) => {
            queue_new(opened, state);
            current
        }
        (_, _) => {
            state.identity = Some(opened.identity);
            state.offset = 0;
            state.columns = None;
            opened.file
        }
    }
}


fn read_chain_step(
    current: &mut File,
    active: bool,
    state: &mut FollowState,
    limits: &Limits,
    counts: &mut Counts,
    out: &mut Vec<EcsEvent>,
) -> Result<bool, KeaError> {
    if active {
        let drained = read_lines(current, state, limits, counts, out)? < limits.max_lines;
        match drained.then(|| state.queued.pop_front()).flatten() {
            Some(next) => {
                counts.restarts += 1;
                state.offset = 0;
                state.columns = None;
                state.identity = Some(next.identity);
                *current = next.file;
                Ok(true)
            }
            None => Ok(false),
        }
    } else {
        Ok(false)
    }
}


fn read_new(opened: Opened, state: &mut FollowState, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>) -> Result<(), KeaError> {
    let mut current = register(opened, state, counts);
    let result = (0..=MAX_OPEN_HANDLES).try_fold(true, |active, _| read_chain_step(&mut current, active, state, limits, counts, out));
    state.open = Some(current);
    result.map(|_| ())
}


fn compacted_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(COMPACTED_SUFFIX);
    PathBuf::from(name)
}


fn recover_row(
    columns: &Columns,
    seen: &mut SeenLeases,
    floor: Option<i64>,
    emit: bool,
    sink: (&Limits, &mut Counts, &mut Vec<EcsEvent>),
    raw: RawLine,
) {
    let (limits, counts, out) = sink;
    match row_text(raw).and_then(|text| convert_row(columns, &text)) {
        Ok(Converted { event, key }) => {
            let older = floor.is_some_and(|oldest| key.0 < oldest);
            if !older && remember(seen, key, limits.max_seen, counts) && emit {
                out.push(event);
                counts.recovered += 1;
            }
        }
        Err(error) => count_malformed(counts, &error),
    }
}


fn handle_compacted_line(
    held: &mut Compacted,
    seen: &mut SeenLeases,
    limits: &Limits,
    counts: &mut Counts,
    out: &mut Vec<EcsEvent>,
    raw: RawLine,
) -> Result<(), KeaError> {
    match held.columns.as_ref() {
        None => {
            let columns = header_text(raw)?;
            held.columns = Some(columns);
        }
        Some(columns) => recover_row(columns, seen, held.floor, held.emit, (limits, counts, out), raw),
    }
    Ok(())
}


/// Reads up to `max_lines` lines of the held compacted file from its saved offset; returns the lines read.
fn read_held(held: &mut Compacted, seen: &mut SeenLeases, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>) -> Result<usize, KeaError> {
    let file = held.file.try_clone()?;
    let mut reader = BufReader::new(&file);
    reader.seek(SeekFrom::Start(held.offset))?;
    from_fn(|| next_line(&mut reader, limits.max_line).transpose())
        .take(limits.max_lines)
        .try_fold(0, |read, item| {
            let (raw, end) = item?;
            handle_compacted_line(held, seen, limits, counts, out, raw)?;
            held.offset = end;
            Ok::<usize, KeaError>(read + 1)
        })
}


fn continue_compacted(state: &mut FollowState, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>) {
    match state.compacted.take() {
        Some(mut held) if !held.done => {
            match read_held(&mut held, &mut state.seen, limits, counts, out) {
                Ok(read) => held.done = read < limits.max_lines,
                Err(error) => {
                    counts.unrecovered += 1;
                    held.done = true;
                    warn!(%error, "the compacted lease file could not be read");
                }
            }
            state.compacted = Some(held);
        }
        other => state.compacted = other,
    }
}


fn count_unrecovered(state: &mut FollowState, counts: &mut Counts, rotated: bool) {
    if rotated && !state.missing_counted {
        state.missing_counted = true;
        counts.unrecovered += 1;
        warn!("a rotation was seen but the compacted lease file could not be read: leases may be missing");
    }
}


fn replace_compacted(state: &mut FollowState, counts: &mut Counts, file: File, identity: FileIdentity, emit: bool) {
    if state.compacted.as_ref().is_some_and(|held| !held.done) {
        counts.unrecovered += 1;
        warn!("the compacted lease file was replaced before its end was read: leases may be missing");
    }
    state.compacted = Some(Compacted {
        file,
        identity,
        offset: 0,
        columns: None,
        floor: state.seen.first().map(|key| key.0),
        emit,
        done: false,
    });
}


/// Follows `<path>.2` (Kea's compacted state): a new identity is read from its header over as many polls as its length needs, so rows lost to a rotation that was never seen come back here.
fn recover_compacted(
    path: &Path,
    state: &mut FollowState,
    limits: &Limits,
    counts: &mut Counts,
    out: &mut Vec<EcsEvent>,
    first: bool,
    rotated: bool,
) {
    match open_regular(&compacted_path(path)) {
        Ok(Some((file, found, _))) => {
            state.missing_counted = false;
            if state.compacted.as_ref().map(|held| held.identity) != Some(found) {
                replace_compacted(state, counts, file, found, !first);
            }
        }
        Ok(None) => count_unrecovered(state, counts, rotated),
        Err(error) => {
            debug!(%error, "the compacted lease path is not readable");
            count_unrecovered(state, counts, rotated);
        }
    }
    continue_compacted(state, limits, counts, out);
}


fn column_count_refusals(counts: &Counts) -> u64 {
    counts.malformed.get(COLUMN_COUNT_KIND).copied().unwrap_or(0)
}


fn warn_column_count(before: u64, counts: &Counts) {
    let total = column_count_refusals(counts);
    if total > before {
        warn!(total, "lease rows with a wrong field count were left out");
    }
}


/// Reads the lines added since the last call into `out`; a replaced file is first read to its end through the old handle, then the new one is read from its header; a shorter file restarts at the header, a non-regular file is refused.
pub fn poll(path: &Path, state: &mut FollowState, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>) -> Result<(), KeaError> {
    match open_regular(path)? {
        None => {
            counts.absent += 1;
            Ok(())
        }
        Some((file, identity, length)) => {
            let before = column_count_refusals(counts);
            let first = state.identity.is_none();
            let restarts = counts.restarts;
            let result = read_new(Opened { file, identity, length }, state, limits, counts, out);
            recover_compacted(path, state, limits, counts, out, first, counts.restarts > restarts);
            warn_column_count(before, counts);
            result
        }
    }
}


/// The counts as one `kind=count` list, never any row content.
pub fn malformed_summary(counts: &Counts) -> String {
    counts
        .malformed
        .iter()
        .map(|(kind, number)| format!("{kind}={number}"))
        .collect::<Vec<String>>()
        .join(",")
}
