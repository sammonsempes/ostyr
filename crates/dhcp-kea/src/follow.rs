use crate::error::{HeaderError, KeaError, RowError};
use crate::header::{parse_header, Columns};
use crate::row::{convert_row, Converted};
use crate::types::{FileIdentity, LeaseKey, MalformedCounts, SeenLeases};
use core_export::ecs::EcsEvent;
use ecs_normalise::stream::{read_raw_line, RawLine};
use std::fs::{symlink_metadata, File, Metadata};
use std::io::{self, BufReader, Seek, SeekFrom};
use std::iter::from_fn;
use std::path::Path;
use tracing::warn;


pub const MAX_LINE_BYTES: u64 = 65_536;


pub const MAX_SEEN_LEASES: usize = 100_000;


pub const MAX_LINES_PER_POLL: usize = 10_000;


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


/// Where the reader stands in the file: its identity, the offset of the next unread line and the columns read from the header.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FollowState {
    pub identity: Option<FileIdentity>,
    pub offset: u64,
    pub columns: Option<Columns>,
    pub seen: SeenLeases,
}


#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts {
    pub processed: u64,
    pub duplicate: u64,
    pub evicted: u64,
    pub restarts: u64,
    pub absent: u64,
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


/// The file opened must be the regular file the path named a moment before.
pub fn verify(linked: &Metadata, opened: &Metadata) -> Result<FileIdentity, KeaError> {
    if opened.is_file() && identity(linked) == identity(opened) {
        Ok(identity(opened))
    } else {
        Err(KeaError::Replaced)
    }
}


fn open_checked(path: &Path, linked: &Metadata) -> Result<(File, FileIdentity, u64), KeaError> {
    if linked.file_type().is_file() {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let found = verify(linked, &metadata)?;
        Ok((file, found, metadata.len()))
    } else {
        Err(KeaError::NotRegular)
    }
}


fn open_regular(path: &Path) -> Result<Option<(File, FileIdentity, u64)>, KeaError> {
    match symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(KeaError::Io(error)),
        Ok(linked) => open_checked(path, &linked).map(Some),
    }
}


fn complete(raw: &RawLine, start: u64, end: u64) -> bool {
    match raw {
        RawLine::Text(bytes) => end - start > bytes.len() as u64,
        RawLine::TooLong => true,
    }
}


fn next_line(reader: &mut BufReader<File>, max_line: u64) -> io::Result<Option<(RawLine, u64)>> {
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


fn read_new(
    file: File,
    found: FileIdentity,
    length: u64,
    state: &mut FollowState,
    limits: &Limits,
    counts: &mut Counts,
    out: &mut Vec<EcsEvent>,
) -> Result<(), KeaError> {
    if state.identity != Some(found) || length < state.offset {
        counts.restarts += u64::from(state.identity.is_some());
        state.offset = 0;
        state.columns = None;
    }
    state.identity = Some(found);
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(state.offset))?;
    from_fn(|| next_line(&mut reader, limits.max_line).transpose())
        .take(limits.max_lines)
        .try_for_each(|item| {
            let (raw, end) = item?;
            handle_line(state, limits, counts, out, raw)?;
            state.offset = end;
            Ok::<(), KeaError>(())
        })
}


/// Reads the lines added since the last call into `out`; a new identity or a shorter file restarts at the header, a non-regular file is refused.
pub fn poll(path: &Path, state: &mut FollowState, limits: &Limits, counts: &mut Counts, out: &mut Vec<EcsEvent>) -> Result<(), KeaError> {
    match open_regular(path)? {
        None => {
            counts.absent += 1;
            Ok(())
        }
        Some((file, found, length)) => read_new(file, found, length, state, limits, counts, out),
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
