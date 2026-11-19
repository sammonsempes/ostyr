use crate::spool::TAIL_QUARANTINE_BYTES;
use core_audit::error::AuditError;
use core_audit::log::{append_declared, AuditLog};
use core_audit::model::{NewEntry, Record};
use core_config::reload::{bounded_parameter, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use std::fs::File;
use std::io::{self, BufRead, Read};
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;


pub const DEBOUNCE_MILLIS: u64 = 300;


pub fn debounce() -> Duration {
    Duration::from_millis(DEBOUNCE_MILLIS)
}


/// The presence record key kept beside the reload keys.
pub const PRESENCE_DECLARED_KEY: &str = "silent_seconds";


/// The parameter keys this crate's records may keep: the reload keys and the presence key; any other value is stored as `[REDACTED]`.
pub static AGENT_CHANNEL_DECLARED_KEYS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| RELOAD_DECLARED_KEYS.iter().copied().chain([PRESENCE_DECLARED_KEY]).collect());


/// Appends with declared keys, every value first cut with a visible marker naming the characters omitted.
pub fn append_bounded<Output: std::io::Write>(log: &AuditLog<Output>, entry: NewEntry) -> Result<Record, AuditError> {
    let parameters = entry
        .parameters
        .iter()
        .map(|(key, value)| (key.clone(), bounded_parameter(key, value)))
        .collect();
    append_declared(log, NewEntry { parameters, ..entry }, AGENT_CHANNEL_DECLARED_KEYS.as_slice())
}


/// An audit function appending to the shared platform audit log.
pub fn shared_log_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let shared = Arc::clone(log);
    Box::new(move |entry| append_bounded(&shared, entry))
}


/// Passes the audit record on; a failed append is logged at error level as an alert (the engine then keeps the old list in force).
pub fn alerting_audit(inner: Box<SharedAuditFn>) -> Box<SharedAuditFn> {
    Box::new(move |entry| inner(entry).inspect_err(|error| tracing::error!(%error, "ALERT: reload audit append failed, old configuration kept")))
}


pub fn reload_context(target: &Path, module: &str, tenant: &str, request_id: &str) -> ReloadContext {
    ReloadContext {
        actor_id: module.to_owned(),
        tenant: tenant.to_owned(),
        module: module.to_owned(),
        target: target.display().to_string(),
        request_id: request_id.to_owned(),
    }
}


/// `SIGHUP` reloads the engine; dropping the result stops it.
#[cfg(unix)]
pub fn keep_signals<Config: Send + Sync + 'static>(engine: Arc<ReloadEngine<Config>>) -> io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub fn keep_signals<Config: Send + Sync + 'static>(_engine: Arc<ReloadEngine<Config>>) -> io::Result<impl Sized> {
    Ok(())
}


/// Bytes read beyond the limit to tell a line of exactly the limit from a longer one: one more byte and the newline.
pub const LINE_SLACK: u64 = 2;


/// One line of a bounded read: the text, or the bytes consumed by a line longer than the limit, newline included (its rest is skipped, never buffered).
#[derive(Debug, PartialEq, Eq)]
pub enum BoundedLine {
    Text(String),
    Oversized { bytes: usize },
}


/// Reads one line of at most `limit` bytes; `None` at the end of the input.
pub fn read_bounded_line<Input: BufRead + ?Sized>(reader: &mut Input, limit: usize) -> io::Result<Option<BoundedLine>> {
    read_line_ended(reader, limit).map(|read| read.map(|(line, _)| line))
}


/// One undecoded line: its bytes, or the bytes consumed by a line longer than the limit (newline included); and whether a newline ended it (an oversized line counts as ended: it is skipped, never used).
#[derive(Debug, PartialEq, Eq)]
pub struct RawLine {
    pub content: Result<Vec<u8>, usize>,
    pub complete: bool,
}


/// Reads one line of at most `limit` bytes without decoding it; `None` at the end of the input.
pub fn read_raw_line<Input: BufRead + ?Sized>(reader: &mut Input, limit: usize) -> io::Result<Option<RawLine>> {
    let mut buffer = Vec::new();
    let read = Read::take(&mut *reader, u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(LINE_SLACK)).read_until(b'\n', &mut buffer)?;
    if read == 0 {
        Ok(None)
    } else {
        let complete = buffer.ends_with(b"\n");
        if complete {
            buffer.pop();
        }
        if buffer.len() > limit {
            let skipped = if complete { 1 } else { reader.skip_until(b'\n')? };
            Ok(Some(RawLine {
                content: Err(buffer.len().saturating_add(skipped)),
                complete: true,
            }))
        } else {
            Ok(Some(RawLine {
                content: Ok(buffer),
                complete,
            }))
        }
    }
}


/// An `InvalidData` error naming only the offset of the first invalid byte, never the bytes.
pub fn invalid_utf8(error: &std::string::FromUtf8Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("line is not valid UTF-8 at byte {}", error.utf8_error().valid_up_to()),
    )
}


/// The decoded line of a raw one and whether a newline ended it; invalid UTF-8 is `InvalidData`.
pub fn decode_line(raw: RawLine) -> io::Result<(BoundedLine, bool)> {
    match raw.content {
        Ok(bytes) => String::from_utf8(bytes)
            .map(|text| (BoundedLine::Text(text), raw.complete))
            .map_err(|error| invalid_utf8(&error)),
        Err(bytes) => Ok((BoundedLine::Oversized { bytes }, raw.complete)),
    }
}


/// `read_bounded_line` with whether a newline ended the line.
pub fn read_line_ended<Input: BufRead + ?Sized>(reader: &mut Input, limit: usize) -> io::Result<Option<(BoundedLine, bool)>> {
    read_raw_line(reader, limit)?.map(decode_line).transpose()
}


/// One complete spool line: its text, the bytes consumed by an oversized one, or one that is not UTF-8 (offset of the first invalid byte, length, a lossy head bounded by `TAIL_QUARANTINE_BYTES`).
#[derive(Debug, PartialEq, Eq)]
pub enum SpoolLine {
    Text(String),
    Oversized { bytes: usize },
    Invalid { valid_up_to: usize, bytes: usize, head: String },
}


/// The spool line of a raw one; a line that is not UTF-8 is a value, never an error.
pub fn decode_spool_line(raw: RawLine) -> SpoolLine {
    match raw.content {
        Ok(content) => String::from_utf8(content).map_or_else(
            |error| {
                let valid_up_to = error.utf8_error().valid_up_to();
                let invalid = error.into_bytes();
                let head = String::from_utf8_lossy(invalid.get(..TAIL_QUARANTINE_BYTES).unwrap_or(invalid.as_slice())).into_owned();
                SpoolLine::Invalid {
                    valid_up_to,
                    bytes: invalid.len(),
                    head,
                }
            },
            SpoolLine::Text,
        ),
        Err(bytes) => SpoolLine::Oversized { bytes },
    }
}


/// The lines of a reader ended by a newline, each at most `limit` bytes; an unterminated last line is left out and never decoded (a producer may still be writing it, or died mid-character).
pub fn terminated_lines<Input: BufRead + ?Sized>(reader: &mut Input, limit: usize) -> impl Iterator<Item = io::Result<SpoolLine>> + '_ {
    std::iter::repeat_with(move || read_raw_line(reader, limit))
        .map_while(Result::transpose)
        .map_while(|read| match read {
            Ok(raw) if raw.complete => Some(Ok(decode_spool_line(raw))),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
}


/// The lines of a reader, each at most `limit` bytes, until the end or the first read error.
pub fn bounded_lines<Input: BufRead + ?Sized>(reader: &mut Input, limit: usize) -> impl Iterator<Item = io::Result<BoundedLine>> + '_ {
    std::iter::repeat_with(move || read_bounded_line(reader, limit)).map_while(Result::transpose)
}
