use crate::agent_app::AgentFile;
use crate::app::{terminated_lines, SpoolLine};
use crate::error::AppError;
use crate::model::DEFAULT_MAX_MESSAGE_BYTES;
use crate::proto::EventBatch;
use crate::types::LoadFn;
use core_audit::log::owner_only;
use prost::encoding::encoded_len_varint;
use prost::Message;
use same_file::Handle;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;


/// Name prefix of the private temporary file of a quarantine rewrite.
pub const QUARANTINE_TEMPORARY_PREFIX: &str = ".quarantine-";


/// Event lines claimed from the spool file per run; the rest goes back to the spool for the next run.
pub const MAX_SPOOL_BATCHES: usize = 1_000;


pub const SENDING_SUFFIX: &str = ".sending";


pub const TEMPORARY_SUFFIX: &str = ".tmp";


pub const ASIDE_SUFFIX: &str = ".old";


pub const REJECTED_SUFFIX: &str = ".rejected";


/// Messages of the largest size the quarantine file holds.
pub const REJECTED_MESSAGES: u64 = 16;


/// Size cap of the quarantine file; past it the oldest lines are dropped and counted.
pub const MAX_REJECTED_BYTES: u64 = REJECTED_MESSAGES * DEFAULT_MAX_MESSAGE_BYTES as u64;


/// Line cap of the quarantine file as a whole; past it the oldest lines are dropped and counted.
pub const MAX_REJECTED_LINES: u64 = 10_000;


/// Bytes of the field tag of `ecs_json` in the encoded `EventBatch`.
pub const FIELD_TAG_BYTES: usize = 1;


/// The claimed batch and the file holding it until every batch is acknowledged.
#[derive(Debug, Clone)]
pub struct Spool {
    pub batches: Vec<EventBatch>,
    pub sending: PathBuf,
    pub sending_bytes: u64,
    pub sequence_file: PathBuf,
    pub state: SequenceState,
}


/// What a claim read from the claimed file under its lock (`returned`: overflow lines went back to the spool, the file is still to be cut); the default is no claimed file.
#[derive(Debug, Default)]
pub struct Claimed {
    pub lines: Vec<String>,
    pub state: SequenceState,
    pub sending_bytes: u64,
    pub returned: bool,
}


/// The sequence file: the last sequence handed out and how many lines the claimed batch holds (its sequences are `used - count + 1 ..= used`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SequenceState {
    pub used: u64,
    pub count: u64,
}


pub fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}


/// A missing file is the initial state; anything else that is not `<used> <count>` is refused.
pub fn read_sequence(path: &Path) -> Result<SequenceState, AppError> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut fields = text.split_whitespace().map(str::parse::<u64>);
            match (fields.next(), fields.next(), fields.next()) {
                (Some(Ok(used)), Some(Ok(count)), None) => Ok(SequenceState { used, count }),
                _ => Err(AppError::Sequence(path.to_path_buf())),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SequenceState::default()),
        Err(error) => Err(AppError::Io(error)),
    }
}


/// Written to a temporary file, synced, then renamed over the old one.
pub fn write_sequence(path: &Path, state: SequenceState) -> Result<(), AppError> {
    let temporary = suffixed(path, TEMPORARY_SUFFIX);
    let mut out = owner_only(OpenOptions::new().write(true).create(true).truncate(true)).open(&temporary)?;
    writeln!(out, "{} {}", state.used, state.count)?;
    out.sync_all()?;
    Ok(fs::rename(&temporary, path)?)
}


/// The longest spool line whose `EventBatch` (largest sequence, the agent's names, tag and length prefix of the line) encodes within the message limit.
pub fn line_limit(file: &AgentFile) -> usize {
    let fixed = EventBatch {
        sequence: u64::MAX,
        ecs_json: Vec::new(),
        tenant: file.tenant.clone(),
        agent_id: file.agent_id.clone(),
    }
    .encoded_len();
    let prefix = FIELD_TAG_BYTES + encoded_len_varint(DEFAULT_MAX_MESSAGE_BYTES as u64);
    DEFAULT_MAX_MESSAGE_BYTES.saturating_sub(fixed + prefix)
}


/// Lossy heads of refused lines kept per scan for the quarantine; the rest are counted.
pub const MAX_QUARANTINED_LINES: usize = 1_000;


/// Refused lines logged one by one per scan pass; a summary line follows.
pub const MAX_REFUSAL_WARNINGS: u64 = 10;


/// The refused lines of a scan: at most `MAX_QUARANTINED_LINES` lossy heads within `MAX_REJECTED_BYTES`, and the counts (`counts_only`: no head is built).
#[derive(Debug, Default)]
pub struct RefusedLines {
    pub lines: Vec<String>,
    pub bytes: u64,
    pub oversized: u64,
    pub invalid: u64,
    pub dropped: u64,
    pub counts_only: bool,
}


/// How many lines the scan refused, oversized and non-UTF-8 together.
pub fn refused_total(refused: &RefusedLines) -> u64 {
    refused.oversized + refused.invalid
}


/// Keeps the lossy head of a refused line unless `MAX_QUARANTINED_LINES` heads or `MAX_REJECTED_BYTES` are reached (the head is built only under the count cap), otherwise counts it dropped.
pub fn keep_head(refused: &mut RefusedLines, content: &[u8]) {
    let kept = if refused.counts_only || refused.lines.len() >= MAX_QUARANTINED_LINES {
        None
    } else {
        let head = String::from_utf8_lossy(content.get(..TAIL_QUARANTINE_BYTES).unwrap_or(content)).into_owned();
        let total = refused.bytes + head.len() as u64;
        (total < MAX_REJECTED_BYTES).then_some(head)
    };
    match kept {
        Some(head) => {
            refused.bytes += head.len() as u64 + 1;
            refused.lines.push(head);
        }
        None => refused.dropped += 1,
    }
}


/// Counts an oversized line and logs it while the scan is within `MAX_REFUSAL_WARNINGS` (number and length, never content).
pub fn refuse_oversized(refused: &mut RefusedLines, index: usize, bytes: usize) {
    refused.oversized += 1;
    if refused_total(refused) <= MAX_REFUSAL_WARNINGS {
        let line = index + 1;
        tracing::warn!(line, bytes, "oversized spool line refused");
    }
}


/// Counts a non-UTF-8 line, logs it while the scan is within `MAX_REFUSAL_WARNINGS` (number, length and offset, never bytes) and keeps its head.
pub fn refuse_invalid(refused: &mut RefusedLines, index: usize, valid_up_to: usize, bytes: usize, content: &[u8]) {
    refused.invalid += 1;
    if refused_total(refused) <= MAX_REFUSAL_WARNINGS {
        let line = index + 1;
        tracing::warn!(line, bytes, valid_up_to, "non-UTF-8 spool line refused");
    }
    keep_head(refused, content);
}


/// One summary line of a scan pass that refused something (always written then), with the counts.
pub fn log_refusal_summary(refused: &RefusedLines) {
    let total = refused_total(refused);
    if total > 0 {
        let (oversized, invalid, kept, dropped) = (refused.oversized, refused.invalid, refused.lines.len(), refused.dropped);
        tracing::warn!(total, oversized, invalid, kept, dropped, "spool lines refused");
    }
}


/// One summary line of a quarantine copy pass that refused old lines, with the counts.
pub fn log_quarantine_summary(refused: &RefusedLines) {
    let total = refused_total(refused);
    if total > 0 {
        let (oversized, invalid) = (refused.oversized, refused.invalid);
        tracing::warn!(total, oversized, invalid, "quarantine lines refused and not copied");
    }
}


/// The newline-ended text lines of a reader (an unterminated last line stays out); an oversized or non-UTF-8 line is skipped and recorded in `refused`.
pub fn spool_texts_with<'a, Input: BufRead>(
    reader: &'a mut Input,
    limit: usize,
    refused: &'a mut RefusedLines,
) -> impl Iterator<Item = io::Result<String>> + 'a {
    terminated_lines(reader, limit).enumerate().filter_map(move |(index, line)| match line {
        Ok(SpoolLine::Text(text)) => Some(Ok(text)),
        Ok(SpoolLine::Oversized { bytes }) => {
            refuse_oversized(refused, index, bytes);
            None
        }
        Ok(SpoolLine::Invalid { valid_up_to, bytes, content }) => {
            refuse_invalid(refused, index, valid_up_to, bytes, &content);
            None
        }
        Err(error) => Some(Err(error)),
    })
}


/// Opens the quarantine file, none when there is none yet.
pub fn open_old(path: &Path) -> io::Result<Option<File>> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}


/// How many text lines and bytes (newlines included) the old quarantine holds, streamed through its handle.
pub fn old_totals(old: Option<&File>) -> io::Result<(u64, u64)> {
    let mut ignored = RefusedLines {
        counts_only: true,
        ..RefusedLines::default()
    };
    let mut counted = (0, 0);
    if let Some(file) = old {
        let mut reader = BufReader::new(file);
        counted = spool_texts_with(&mut reader, DEFAULT_MAX_MESSAGE_BYTES, &mut ignored).try_fold(counted, |(lines, bytes), read| {
            read.map(|text| (lines + 1, bytes + text.len() as u64 + 1))
        })?;
    }
    Ok(counted)
}


/// Puts the handle of the old quarantine back at its start for the copying pass.
pub fn rewind_old(old: Option<&File>) -> io::Result<()> {
    old.map_or(Ok(()), |file| {
        let mut handle = file;
        handle.rewind()
    })
}


/// Copies the text lines of the old quarantine to `out`, skipping the oldest while `excess` (bytes, lines) is not gone; a refused old line is counted in `refused`; returns how many it skipped.
pub fn copy_after_excess(old: Option<&File>, excess: (u64, u64), refused: &mut RefusedLines, out: &mut dyn Write) -> io::Result<u64> {
    let mut skipped_bytes = 0;
    let mut skipped_lines = 0;
    if let Some(file) = old {
        let mut reader = BufReader::new(file);
        spool_texts_with(&mut reader, DEFAULT_MAX_MESSAGE_BYTES, refused).try_for_each(|read| {
            let text = read?;
            if skipped_bytes < excess.0 || skipped_lines < excess.1 {
                skipped_bytes += text.len() as u64 + 1;
                skipped_lines += 1;
                Ok(())
            } else {
                writeln!(out, "{text}")
            }
        })?;
    }
    Ok(skipped_lines)
}


/// Streams the old quarantine and the added lines through one `BufWriter` into a private temporary file next to it and renames that over it: the newest lines within `caps` (bytes, lines) stay, the dropped count is logged and returned, a refused old line is summarised; work and memory are bounded by the caps.
pub fn rewrite_quarantine(path: &Path, added: &[String], added_bytes: u64, caps: (u64, u64)) -> io::Result<u64> {
    rewrite_quarantine_with(path, added, added_bytes, caps, open_old)
}


/// `rewrite_quarantine` with the function that opens the old file given; the old file is opened once, counted, rewound and copied through that handle.
pub fn rewrite_quarantine_with(
    path: &Path,
    added: &[String],
    added_bytes: u64,
    caps: (u64, u64),
    open: fn(&Path) -> io::Result<Option<File>>,
) -> io::Result<u64> {
    let old = open(path)?;
    let (old_lines, old_bytes) = old_totals(old.as_ref())?;
    let excess = (
        (old_bytes + added_bytes).saturating_sub(caps.0),
        (old_lines + added.len() as u64).saturating_sub(caps.1),
    );
    rewind_old(old.as_ref())?;
    let temporary = tempfile::Builder::new()
        .prefix(QUARANTINE_TEMPORARY_PREFIX)
        .tempfile_in(path.parent().unwrap_or(Path::new(".")))?;
    let mut out = BufWriter::new(temporary.as_file());
    let mut skipped = RefusedLines {
        counts_only: true,
        ..RefusedLines::default()
    };
    let dropped = copy_after_excess(old.as_ref(), excess, &mut skipped, &mut out)?;
    added.iter().try_for_each(|line| writeln!(out, "{line}"))?;
    out.into_inner().map_err(io::IntoInnerError::into_error)?.sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    log_quarantine_summary(&skipped);
    if dropped > 0 {
        tracing::warn!(dropped, "quarantine full, oldest refused lines dropped");
    }
    Ok(dropped)
}


/// Adds the kept refused heads to the quarantine within `MAX_REJECTED_BYTES` and `MAX_REJECTED_LINES`.
pub fn quarantine_refused(spool: &Path, refused: &RefusedLines) -> io::Result<()> {
    if refused.lines.is_empty() {
        Ok(())
    } else {
        rewrite_quarantine(
            &suffixed(spool, REJECTED_SUFFIX),
            &refused.lines,
            refused.bytes,
            (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        )
        .map(|_| ())
    }
}


/// How many lines the next claim takes: the first `MAX_SPOOL_BATCHES` of the spool.
pub fn count_lines(path: &Path, limit: usize) -> io::Result<u64> {
    count_lines_of(&File::open(path)?, limit)
}


/// `count_lines` on an open file, read through that handle (a lock held on it does not refuse it).
pub fn count_lines_of(file: &File, limit: usize) -> io::Result<u64> {
    count_refused(file, limit).map(|(count, _)| count)
}


/// The count of `count_lines_of` and the non-UTF-8 lines met while counting.
pub fn count_refused(file: &File, limit: usize) -> io::Result<(u64, RefusedLines)> {
    let mut reader = BufReader::new(file);
    let mut refused = RefusedLines::default();
    let taken = spool_texts_with(&mut reader, limit, &mut refused)
        .take(MAX_SPOOL_BATCHES)
        .collect::<io::Result<Vec<_>>>()?;
    log_refusal_summary(&refused);
    Ok((taken.len() as u64, refused))
}


/// The lines joined into one text, each followed by a newline; the first failing line fails the whole text.
pub fn joined_lines(mut lines: &mut dyn Iterator<Item = io::Result<String>>) -> io::Result<String> {
    Iterator::try_fold(&mut lines, String::new(), |mut text, line| {
        text.push_str(&line?);
        text.push('\n');
        Ok(text)
    })
}


/// Lock attempts of one append before it fails with `SPOOL_LOCK_BUSY`.
pub const SPOOL_LOCK_ATTEMPTS: u32 = 3_000;


/// Pause between two lock attempts; with `SPOOL_LOCK_ATTEMPTS` one round lasts about 30 seconds, and an append runs up to `SPOOL_REOPEN_ROUNDS` rounds.
pub const SPOOL_LOCK_PAUSE: Duration = Duration::from_millis(10);


/// The fixed error text of an append that never got the spool lock.
pub const SPOOL_LOCK_BUSY: &str = "spool lock held by another process, append abandoned";


/// The Windows error code of a read refused by a byte-range lock.
pub const WINDOWS_LOCK_VIOLATION: i32 = 33;


/// Sleeps `SPOOL_LOCK_PAUSE`.
pub fn pause_between_lock_attempts() {
    std::thread::sleep(SPOOL_LOCK_PAUSE);
}


/// Takes the lock through `try_lock`, trying at most `attempts` times and calling `pause` after each refusal; the fixed `SPOOL_LOCK_BUSY` error when all fail.
pub fn lock_bounded(attempts: u32, try_lock: &mut dyn FnMut() -> Result<(), TryLockError>, pause: &mut dyn FnMut()) -> io::Result<()> {
    (0..attempts)
        .find_map(|_| match try_lock() {
            Ok(()) => Some(Ok(())),
            Err(TryLockError::WouldBlock) => {
                pause();
                None
            }
            Err(TryLockError::Error(error)) => Some(Err(error)),
        })
        .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::TimedOut, SPOOL_LOCK_BUSY)))
}


/// Whether the error is a Windows read refused because a producer holds the spool lock.
pub fn is_lock_violation(error: &io::Error) -> bool {
    error.raw_os_error() == Some(WINDOWS_LOCK_VIOLATION)
}


/// Appends the lines to the spool in one write under an exclusive lock of the file (released when it closes), creating it only when there is something to append; returns whether it appended.
pub fn append_back(lines: impl Iterator<Item = io::Result<String>>, spool: &Path) -> io::Result<bool> {
    append_locked(lines, spool, SPOOL_LOCK_ATTEMPTS, &mut pause_between_lock_attempts)
}


/// How many times an append opens the spool again after finding, once locked, that the path names another file.
pub const SPOOL_REOPEN_ROUNDS: u32 = 3;


/// Whether the locked handle is still the file at `spool`; a missing or unopenable path (Windows delete-pending) is not.
pub fn is_current_spool(out: &File, spool: &Path) -> io::Result<bool> {
    match Handle::from_path(spool) {
        Ok(current) => Ok(Handle::from_file(out.try_clone()?)? == current),
        Err(error) => {
            tracing::warn!(%error, "spool path not openable after the lock, opening it again");
            Ok(false)
        }
    }
}


/// Opens the spool and locks it, retrying from the open while the locked handle is no longer the file at `spool`; the fixed `SPOOL_LOCK_BUSY` error when the rounds are spent.
pub fn open_locked_with(spool: &Path, attempts: u32, pause: &mut dyn FnMut(), is_current: fn(&File, &Path) -> io::Result<bool>) -> io::Result<File> {
    (0..SPOOL_REOPEN_ROUNDS)
        .find_map(|_| open_locked_once(spool, attempts, pause, is_current).transpose())
        .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::TimedOut, SPOOL_LOCK_BUSY)))
}


/// One round of `open_locked_with`: the locked handle, or none when the path names another file by then.
pub fn open_locked_once(
    spool: &Path,
    attempts: u32,
    pause: &mut dyn FnMut(),
    is_current: fn(&File, &Path) -> io::Result<bool>,
) -> io::Result<Option<File>> {
    let out = owner_only(OpenOptions::new().read(true).write(true).create(true)).open(spool)?;
    lock_bounded(attempts, &mut || out.try_lock(), pause)?;
    Ok(is_current(&out, spool)?.then_some(out))
}


/// Sets a dead unterminated tail aside, then writes the text in one `write_all` at the end under the exclusive lock of the spool, then runs `between` and syncs the same handle, lock still held.
pub fn write_locked(text: &str, spool: &Path, attempts: u32, pause: &mut dyn FnMut(), between: &mut dyn FnMut()) -> io::Result<()> {
    write_locked_with(text, spool, attempts, pause, between, is_current_spool)
}


/// `write_locked` with the identity check given.
pub fn write_locked_with(
    text: &str,
    spool: &Path,
    attempts: u32,
    pause: &mut dyn FnMut(),
    between: &mut dyn FnMut(),
    is_current: fn(&File, &Path) -> io::Result<bool>,
) -> io::Result<()> {
    let mut out = open_locked_with(spool, attempts, pause, is_current)?;
    cut_tail(spool, &out)?;
    out.seek(SeekFrom::End(0))?;
    out.write_all(text.as_bytes())?;
    between();
    out.sync_all()
}


/// `append_back` with the lock attempts and the pause between them given.
pub fn append_locked(lines: impl Iterator<Item = io::Result<String>>, spool: &Path, attempts: u32, pause: &mut dyn FnMut()) -> io::Result<bool> {
    append_locked_between(lines, spool, attempts, pause, &mut || ())
}


/// `append_locked` with `between` run after the write and before the sync of the written handle.
pub fn append_locked_between(
    mut lines: impl Iterator<Item = io::Result<String>>,
    spool: &Path,
    attempts: u32,
    pause: &mut dyn FnMut(),
    between: &mut dyn FnMut(),
) -> io::Result<bool> {
    append_dyn(&mut lines, spool, attempts, pause, between)
}


/// The body of `append_locked_between` on a trait object, so one instance holds every branch (a generic one is covered per instantiation).
pub fn append_dyn(
    lines: &mut dyn Iterator<Item = io::Result<String>>,
    spool: &Path,
    attempts: u32,
    pause: &mut dyn FnMut(),
    between: &mut dyn FnMut(),
) -> io::Result<bool> {
    let mut rest = lines.peekable();
    if rest.peek().is_some() {
        let text = joined_lines(&mut rest)?;
        write_locked(&text, spool, attempts, pause, between)?;
        Ok(true)
    } else {
        Ok(false)
    }
}


/// How many lines of the spool the next claim takes, or none when a producer holds its lock (Windows): the claim is left for the next run, logged.
pub fn lines_to_claim(path: &Path, limit: usize) -> io::Result<Option<u64>> {
    lines_to_claim_with(path, limit, count_lines)
}


/// `lines_to_claim` with the counting function given.
pub fn lines_to_claim_with(path: &Path, limit: usize, count: fn(&Path, usize) -> io::Result<u64>) -> io::Result<Option<u64>> {
    match count(path, limit) {
        Err(error) if is_lock_violation(&error) => {
            tracing::warn!(%error, "spool locked by a producer, claim left for the next run");
            Ok(None)
        }
        other => other.map(Some),
    }
}


/// Writes the lines to the temporary file next to `path`, synced; returns its path.
pub fn write_temporary(path: &Path, lines: &[String]) -> io::Result<PathBuf> {
    let temporary = suffixed(path, TEMPORARY_SUFFIX);
    let mut out = owner_only(OpenOptions::new().write(true).create(true).truncate(true)).open(&temporary)?;
    lines.iter().try_for_each(|line| writeln!(out, "{line}"))?;
    out.sync_all()?;
    Ok(temporary)
}


/// Rewrites the claimed file to the given lines, unless its length is no longer `expected` (a late producer write): then it is kept and false returned.
pub fn rewrite_lines(path: &Path, lines: &[String], expected: u64) -> io::Result<bool> {
    rewrite_lines_between(path, lines, expected, || ())
}


/// `rewrite_lines` with `between` run after the old file got its second name and before the rename; the length is read on the old file after the swap.
pub fn rewrite_lines_between(path: &Path, lines: &[String], expected: u64, between: impl FnOnce()) -> io::Result<bool> {
    let temporary = write_temporary(path, lines)?;
    let aside = suffixed(path, ASIDE_SUFFIX);
    match fs::remove_file(&aside) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error)?,
        Ok(()) | Err(_) => (),
    }
    fs::hard_link(path, &aside)?;
    between();
    fs::rename(&temporary, path)?;
    if fs::metadata(&aside)?.len() == expected {
        fs::remove_file(&aside)?;
        Ok(true)
    } else {
        tracing::warn!("claimed spool grew while it was read, left whole for the next run");
        fs::rename(&aside, path)?;
        Ok(false)
    }
}


/// Adds the refused batches to the quarantine file, dropping the oldest lines past `max_bytes` or `MAX_REJECTED_LINES`; returns how many were dropped (logged).
pub fn quarantine(path: &Path, rejected: &[EventBatch], max_bytes: u64) -> io::Result<u64> {
    if rejected.is_empty() {
        Ok(0)
    } else {
        let added = rejected
            .iter()
            .enumerate()
            .map(|(index, batch)| {
                String::from_utf8(batch.ecs_json.clone()).map_err(|error| {
                    let cause = crate::app::invalid_utf8(&error);
                    io::Error::new(io::ErrorKind::InvalidData, format!("rejected batch {index}: {cause}"))
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let added_bytes = added.iter().map(|line| line.len() as u64 + 1).sum();
        rewrite_quarantine(path, &added, added_bytes, (max_bytes, MAX_REJECTED_LINES))
    }
}


/// Bytes of overflow lines appended back to the spool per write (a chunk ends once it holds at least this many).
pub const RETURN_CHUNK_BYTES: usize = 65_536;


/// The next chunk of lines: lines are taken until their bytes (newline included) reach `RETURN_CHUNK_BYTES`.
pub fn next_chunk(rest: &mut dyn Iterator<Item = io::Result<String>>) -> io::Result<Vec<String>> {
    let mut size = 0;
    std::iter::from_fn(|| {
        (size < RETURN_CHUNK_BYTES)
            .then(|| rest.next())
            .flatten()
            .inspect(|line| size += line.as_ref().map_or(1, |text| text.len() + 1))
    })
    .collect()
}


/// Appends the lines back to the spool in bounded chunks, one write each; returns how many writes it made.
pub fn append_chunks(lines: impl Iterator<Item = io::Result<String>>, spool: &Path) -> io::Result<u64> {
    let mut rest = lines.peekable();
    std::iter::from_fn(|| rest.peek().is_some().then(|| next_chunk(&mut rest)))
        .try_fold(0, |writes, chunk| append_back(chunk?.into_iter().map(Ok), spool).map(|_| writes + 1))
}


/// The first `count` lines of the locked claimed file, read through its handle, and whether further lines went back to the spool (the claimed file is then still to be cut to the first lines, once its handle is closed).
pub fn load_claimed(claimed: &File, spool: &Path, count: u64, limit: usize) -> io::Result<(Vec<String>, bool)> {
    let mut stream = claimed;
    stream.rewind()?;
    let mut reader = BufReader::new(claimed);
    let mut refused = RefusedLines::default();
    let mut texts = spool_texts_with(&mut reader, limit, &mut refused);
    let wanted = usize::try_from(count).unwrap_or(MAX_SPOOL_BATCHES).min(MAX_SPOOL_BATCHES);
    let first = texts.by_ref().take(wanted).collect::<io::Result<Vec<_>>>()?;
    let returned = append_chunks(texts, spool)? > 0;
    log_refusal_summary(&refused);
    quarantine_refused(spool, &refused)?;
    Ok((first, returned))
}


/// The claimed lines, or none when a producer holds the lock of the claimed file (Windows): the claim is left for the next run, logged.
pub fn claimed_lines_with(claimed: &File, spool: &Path, count: u64, limit: usize, load: LoadFn) -> io::Result<Option<(Vec<String>, bool)>> {
    match load(claimed, spool, count, limit) {
        Err(error) if is_lock_violation(&error) => {
            tracing::warn!(%error, "claimed spool locked by a producer, left for the next run");
            Ok(None)
        }
        other => other.map(Some),
    }
}


/// Renames a fresh spool to the sending file after recording the new sequences, unless a sending file is already there (a crashed run), with the lock attempts and the pause given; the count, the sequence record and the rename all run under the spool lock, so no append is half written.
pub fn claim_fresh_with(file: &AgentFile, sending: &Path, attempts: u32, pause: &mut dyn FnMut()) -> Result<(), AppError> {
    if !sending.try_exists()? && file.spool_file.try_exists()? {
        let spool = OpenOptions::new().read(true).write(true).open(&file.spool_file)?;
        match lock_bounded(attempts, &mut || spool.try_lock(), pause) {
            Ok(()) => claim_locked(file, sending, &spool),
            Err(error) => {
                tracing::warn!(%error, "spool not locked, claim left for the next run");
                Ok(())
            }
        }
    } else {
        Ok(())
    }
}


/// Once locked, claims only when the handle is still the spool and no sending file exists (another claim got there first: logged, left for the next run).
pub fn claim_locked(file: &AgentFile, sending: &Path, spool: &File) -> Result<(), AppError> {
    if is_current_spool(spool, &file.spool_file)? && !sending.try_exists()? {
        claim_counted(file, sending, spool)
    } else {
        tracing::warn!("spool claimed by another run meanwhile, claim left for the next run");
        Ok(())
    }
}


/// Sets the dead tail of the locked spool aside, counts its lines (a spool of refused non-UTF-8 lines only is quarantined and emptied), records the sequences and renames it to `sending` (the lock and the checks of `claim_locked` stand for a no-replace rename); a spool without a complete line stays.
pub fn claim_counted(file: &AgentFile, sending: &Path, spool: &File) -> Result<(), AppError> {
    cut_tail(&file.spool_file, spool)?;
    let mut stream = spool;
    stream.rewind()?;
    let (count, refused) = count_refused(spool, line_limit(file))?;
    if count == 0 && refused_total(&refused) > 0 {
        quarantine_refused(&file.spool_file, &refused)?;
        Ok(spool.set_len(0)?)
    } else if count > 0 {
        let state = read_sequence(&file.sequence_file)?;
        let used = state
            .used
            .checked_add(count)
            .ok_or_else(|| AppError::SequenceOverflow(file.sequence_file.clone()))?;
        write_sequence(&file.sequence_file, SequenceState { used, count })?;
        Ok(fs::rename(&file.spool_file, sending)?)
    } else {
        Ok(())
    }
}


/// The start of the last newline-separated segment of the file, read from its current position.
pub fn last_segment_start(file: &File) -> io::Result<u64> {
    let mut reader = BufReader::new(file);
    std::iter::repeat_with(|| reader.skip_until(b'\n'))
        .take_while(|read| !matches!(read, Ok(0)))
        .try_fold((0, 0), |(_, end), bytes| Ok((end, end + bytes? as u64)))
        .map(|(start, _)| start)
}


/// A lossy text turns an invalid byte into three bytes, so the quarantined tail is a third of the message limit at most.
pub const REPLACEMENT_FACTOR: usize = 3;


/// Bytes of an unterminated tail kept in the quarantine (the rest is counted in the log only).
pub const TAIL_QUARANTINE_BYTES: usize = DEFAULT_MAX_MESSAGE_BYTES / REPLACEMENT_FACTOR;


/// Moves the bytes after the last newline of the locked file to the quarantine of `spool` and cuts the file there; nothing when it ends in a newline. Under the lock such a tail is always dead (a crashed or failed appender), so it is never completed.
pub fn cut_tail(spool: &Path, locked: &File) -> io::Result<()> {
    let length = locked.metadata()?.len();
    let mut handle = locked;
    if length == 0 {
        Ok(())
    } else {
        handle.seek(SeekFrom::Start(length - 1))?;
        let mut last = [u8::MIN; 1];
        handle.read_exact(&mut last)?;
        if last == *b"\n" {
            Ok(())
        } else {
            handle.rewind()?;
            let start = last_segment_start(locked)?;
            handle.seek(SeekFrom::Start(start))?;
            let mut tail = Vec::new();
            Read::take(&mut handle, TAIL_QUARANTINE_BYTES as u64).read_to_end(&mut tail)?;
            let batch = EventBatch {
                ecs_json: String::from_utf8_lossy(&tail).into_owned().into_bytes(),
                ..EventBatch::default()
            };
            quarantine(&suffixed(spool, REJECTED_SUFFIX), &[batch], MAX_REJECTED_BYTES)?;
            let bytes = length - start;
            tracing::warn!(bytes, "unterminated tail set aside in the quarantine");
            Ok(locked.set_len(start)?)
        }
    }
}


/// One event batch per line, numbered from `first`.
pub fn batches_of(lines: Vec<String>, first: u64, file: &AgentFile) -> Vec<EventBatch> {
    lines
        .into_iter()
        .zip(0..)
        .map(|(text, offset)| EventBatch {
            sequence: first.saturating_add(offset),
            ecs_json: text.into_bytes(),
            tenant: file.tenant.clone(),
            agent_id: file.agent_id.clone(),
        })
        .collect()
}


/// Claims the spool: sequences continue from the sequence file across runs and a crashed claim is resent with the same sequences.
pub fn claim_spool(file: &AgentFile) -> Result<Spool, AppError> {
    claim_spool_with(file, load_claimed)
}


/// `claim_spool` with the loading function given; a claimed file that is locked keeps its bytes (`sending_bytes` of `u64::MAX`, never equal to its length) so `finish_spool` cannot remove it.
pub fn claim_spool_with(file: &AgentFile, load: LoadFn) -> Result<Spool, AppError> {
    claim_spool_in(file, load, SPOOL_LOCK_ATTEMPTS, &mut pause_between_lock_attempts)
}


/// `claim_spool_with` with the lock attempts and the pause given.
pub fn claim_spool_in(file: &AgentFile, load: LoadFn, attempts: u32, pause: &mut dyn FnMut()) -> Result<Spool, AppError> {
    let sending = suffixed(&file.spool_file, SENDING_SUFFIX);
    claim_fresh_with(file, &sending, attempts, pause)?;
    let loaded = match open_sending(&sending)? {
        Some(handle) => load_sending(file, &sending, &handle, load, attempts, pause)?,
        None => Claimed {
            state: read_sequence(&file.sequence_file)?,
            ..Claimed::default()
        },
    };
    let claimed = cut_returned(&sending, loaded)?;
    let first = claimed
        .state
        .used
        .saturating_sub(claimed.state.count)
        .checked_add(1)
        .ok_or_else(|| AppError::SequenceOverflow(file.sequence_file.clone()))?;
    Ok(Spool {
        batches: batches_of(claimed.lines, first, file),
        sending,
        sending_bytes: claimed.sending_bytes,
        sequence_file: file.sequence_file.clone(),
        state: claimed.state,
    })
}


/// Cuts the claimed file to the lines taken once the lock handle is closed (a rename over an open file is refused on Windows); if a late write made it longer it stays whole and its bytes stay those read, so `finish_spool` keeps it.
pub fn cut_returned(sending: &Path, claimed: Claimed) -> Result<Claimed, AppError> {
    let rewritten = claimed.returned && rewrite_lines(sending, &claimed.lines, claimed.sending_bytes)?;
    let sending_bytes = if rewritten {
        fs::metadata(sending)?.len()
    } else {
        claimed.sending_bytes
    };
    Ok(Claimed { sending_bytes, ..claimed })
}


/// Opens the claimed file, none when there is none (another run removed it meanwhile).
pub fn open_sending(sending: &Path) -> io::Result<Option<File>> {
    match OpenOptions::new().read(true).write(true).open(sending) {
        Ok(handle) => Ok(Some(handle)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}


/// A claim that read nothing and keeps the claimed file whole (`sending_bytes` of `u64::MAX`).
pub fn deferred_claim() -> Claimed {
    Claimed {
        sending_bytes: u64::MAX,
        ..Claimed::default()
    }
}


/// Locks the claimed file and, if the handle is still the file at `sending`, reads everything the claim needs through it; otherwise defers, logged.
pub fn load_sending(
    file: &AgentFile,
    sending: &Path,
    handle: &File,
    load: LoadFn,
    attempts: u32,
    pause: &mut dyn FnMut(),
) -> Result<Claimed, AppError> {
    match lock_bounded(attempts, &mut || handle.try_lock(), pause) {
        Ok(()) if is_current_spool(handle, sending)? => read_locked(file, handle, load),
        Ok(()) => {
            tracing::warn!("claimed spool replaced while waiting for its lock, left for the next run");
            Ok(deferred_claim())
        }
        Err(error) => {
            tracing::warn!(%error, "claimed spool not locked, left for the next run");
            Ok(deferred_claim())
        }
    }
}


/// Under the lock of the claimed file: its sequence state, its tail set aside, and its lines.
pub fn read_locked(file: &AgentFile, handle: &File, load: LoadFn) -> Result<Claimed, AppError> {
    let state = read_sequence(&file.sequence_file)?;
    cut_tail(&file.spool_file, handle)?;
    let sending_bytes = handle.metadata()?.len();
    match claimed_lines_with(handle, &file.spool_file, state.count, line_limit(file), load)? {
        Some((lines, returned)) => Ok(Claimed {
            lines,
            state,
            sending_bytes,
            returned,
        }),
        None => Ok(Claimed { state, ..deferred_claim() }),
    }
}


/// Removes the claimed file once every batch of it is acknowledged and nothing was appended to it since it was read; otherwise it stays.
pub fn finish_spool(spool: &Spool, acknowledged: &[u64]) -> Result<(), AppError> {
    finish_spool_with(spool, acknowledged, SPOOL_LOCK_ATTEMPTS, &mut pause_between_lock_attempts)
}


/// `finish_spool` with the lock attempts and the pause given; the claimed file is locked across the length check and the removal.
pub fn finish_spool_with(spool: &Spool, acknowledged: &[u64], attempts: u32, pause: &mut dyn FnMut()) -> Result<(), AppError> {
    if spool.batches.iter().all(|batch| acknowledged.contains(&batch.sequence)) && spool.sending.try_exists()? {
        let claimed = OpenOptions::new().read(true).append(true).open(&spool.sending)?;
        match lock_bounded(attempts, &mut || claimed.try_lock(), pause) {
            Ok(()) if finished_file_is_loaded(&claimed, spool)? => Ok(fs::remove_file(&spool.sending)?),
            Ok(()) => {
                tracing::warn!("claimed spool grew or was replaced after it was read, kept for the next run");
                Ok(())
            }
            Err(error) => {
                tracing::warn!(%error, "claimed spool not locked, kept for the next run");
                Ok(())
            }
        }
    } else {
        Ok(())
    }
}


/// Whether the locked claimed file is still the one this claim loaded: the handle is the file at the path, its length and the sequence state are unchanged.
pub fn finished_file_is_loaded(claimed: &File, spool: &Spool) -> Result<bool, AppError> {
    Ok(is_current_spool(claimed, &spool.sending)?
        && claimed.metadata()?.len() == spool.sending_bytes
        && read_sequence(&spool.sequence_file)? == spool.state)
}
