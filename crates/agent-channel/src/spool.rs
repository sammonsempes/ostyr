use crate::agent_app::AgentFile;
use crate::app::{bounded_lines, BoundedLine};
use crate::error::AppError;
use crate::model::DEFAULT_MAX_MESSAGE_BYTES;
use crate::proto::EventBatch;
use core_audit::log::owner_only;
use prost::encoding::encoded_len_varint;
use prost::Message;
use same_file::Handle;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;


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


/// Bytes of the field tag of `ecs_json` in the encoded `EventBatch`.
pub const FIELD_TAG_BYTES: usize = 1;


/// The claimed batch and the file holding it until every batch is acknowledged.
#[derive(Debug, Clone)]
pub struct Spool {
    pub batches: Vec<EventBatch>,
    pub sending: PathBuf,
    pub sending_bytes: u64,
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


/// The text lines of a reader, an oversized one (more than `limit` bytes) skipped with a counted log line (number, length, never the content).
pub fn spool_texts<Input: BufRead>(reader: &mut Input, limit: usize) -> impl Iterator<Item = io::Result<String>> + '_ {
    bounded_lines(reader, limit)
        .enumerate()
        .scan(u64::MIN, |refused, (index, line)| {
            Some(match line {
                Ok(BoundedLine::Text(text)) => Some(Ok(text)),
                Ok(BoundedLine::Oversized { bytes }) => {
                    *refused += 1;
                    tracing::warn!(line = index + 1, bytes, refused = *refused, "oversized spool line refused");
                    None
                }
                Err(error) => Some(Err(error)),
            })
        })
        .flatten()
}


/// How many lines the next claim takes: the first `MAX_SPOOL_BATCHES` of the spool.
pub fn count_lines(path: &Path, limit: usize) -> io::Result<u64> {
    let mut reader = BufReader::new(File::open(path)?);
    let taken = spool_texts(&mut reader, limit).take(MAX_SPOOL_BATCHES).collect::<io::Result<Vec<_>>>()?;
    Ok(taken.len() as u64)
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


/// Pause between two lock attempts; with `SPOOL_LOCK_ATTEMPTS` the deadline is about 30 seconds.
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
    let out = owner_only(OpenOptions::new().read(true).append(true).create(true)).open(spool)?;
    lock_bounded(attempts, &mut || out.try_lock(), pause)?;
    Ok(is_current(&out, spool)?.then_some(out))
}


/// Writes the text in one `write_all` under the exclusive lock of the spool, then runs `between` and syncs the same handle, lock still held.
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
    lines: impl Iterator<Item = io::Result<String>>,
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


/// Adds the refused batches to the quarantine file, dropping the oldest lines past `max_bytes`; returns how many were dropped (logged).
pub fn quarantine(path: &Path, rejected: &[EventBatch], max_bytes: u64) -> io::Result<u64> {
    if rejected.is_empty() {
        Ok(0)
    } else {
        let mut lines = match File::open(path) {
            Ok(file) => spool_texts(&mut BufReader::new(file), DEFAULT_MAX_MESSAGE_BYTES).collect::<io::Result<Vec<_>>>()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => Err(error)?,
        };
        let added = rejected
            .iter()
            .map(|batch| String::from_utf8(batch.ecs_json.clone()).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)))
            .collect::<io::Result<Vec<_>>>()?;
        lines.extend(added);
        let mut total: u64 = lines.iter().map(|line| line.len() as u64 + 1).sum();
        let dropped = lines
            .iter()
            .take_while(|line| {
                let over = total > max_bytes;
                total = total.saturating_sub(line.len() as u64 + 1);
                over
            })
            .count();
        lines.drain(..dropped);
        fs::rename(write_temporary(path, &lines)?, path)?;
        if dropped > 0 {
            tracing::warn!(dropped, "quarantine full, oldest refused batches dropped");
        }
        Ok(dropped as u64)
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


/// The first `count` lines of the claimed file; any further line goes back to the spool and the claimed file is cut to the first lines.
pub fn load_claimed(sending: &Path, spool: &Path, count: u64, limit: usize) -> io::Result<Vec<String>> {
    let (first, returned, length) = {
        let file = File::open(sending)?;
        let length = file.metadata()?.len();
        let mut reader = BufReader::new(file);
        let mut texts = spool_texts(&mut reader, limit);
        let wanted = usize::try_from(count).unwrap_or(MAX_SPOOL_BATCHES).min(MAX_SPOOL_BATCHES);
        let first = texts.by_ref().take(wanted).collect::<io::Result<Vec<_>>>()?;
        let returned = append_chunks(texts, spool)? > 0;
        (first, returned, length)
    };
    if returned {
        rewrite_lines(sending, &first, length)?;
    }
    Ok(first)
}


/// The claimed lines, or none when a producer holds the lock of the claimed file (Windows): the claim is left for the next run, logged.
pub fn claimed_lines_with(
    sending: &Path,
    spool: &Path,
    count: u64,
    limit: usize,
    load: fn(&Path, &Path, u64, usize) -> io::Result<Vec<String>>,
) -> io::Result<Option<Vec<String>>> {
    match load(sending, spool, count, limit) {
        Err(error) if is_lock_violation(&error) => {
            tracing::warn!(%error, "claimed spool locked by a producer, left for the next run");
            Ok(None)
        }
        other => other.map(Some),
    }
}


/// Renames a fresh spool to the sending file after recording the new sequences, unless a sending file is already there (a crashed run).
pub fn claim_fresh(file: &AgentFile, sending: &Path) -> Result<(), AppError> {
    let claimable = if !sending.try_exists()? && file.spool_file.try_exists()? {
        lines_to_claim(&file.spool_file, line_limit(file))?
    } else {
        None
    };
    if let Some(count) = claimable {
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
pub fn claim_spool_with(file: &AgentFile, load: fn(&Path, &Path, u64, usize) -> io::Result<Vec<String>>) -> Result<Spool, AppError> {
    let sending = suffixed(&file.spool_file, SENDING_SUFFIX);
    claim_fresh(file, &sending)?;
    let state = read_sequence(&file.sequence_file)?;
    let (lines, sending_bytes) = if sending.try_exists()? {
        let before = fs::metadata(&sending)?.len();
        match claimed_lines_with(&sending, &file.spool_file, state.count, line_limit(file), load)? {
            Some(lines) => (lines, before.min(fs::metadata(&sending)?.len())),
            None => (Vec::new(), u64::MAX),
        }
    } else {
        (Vec::new(), 0)
    };
    let first = state
        .used
        .saturating_sub(state.count)
        .checked_add(1)
        .ok_or_else(|| AppError::SequenceOverflow(file.sequence_file.clone()))?;
    Ok(Spool {
        batches: batches_of(lines, first, file),
        sending,
        sending_bytes,
    })
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
            Ok(()) if claimed.metadata()?.len() == spool.sending_bytes => Ok(fs::remove_file(&spool.sending)?),
            Ok(()) => {
                tracing::warn!("claimed spool grew after it was read, kept for the next run");
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
