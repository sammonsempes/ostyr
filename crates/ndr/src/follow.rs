//! Follows Suricata's `eve.json` across rotations with a fingerprinted cursor; lines are returned only as complete, bounded, valid UTF-8.


use crate::error::NdrError;
use crate::model::{Cursor, FollowCounts, Follower, Limits, Ticked};
use crate::reader::FILE_FLAGS;
use crate::types::OpenEveFn;
use core_config::trusted_dir::open_trusted_dir;
use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::ControlFlow;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::Arc;


pub const CHUNK_BYTES: usize = 65_536;


pub const MAX_CHUNKS: usize = 4_096;


pub const HEAD_BYTES: usize = 4_096;


pub const MAX_STATE_BYTES: u64 = 4_096;


const STATE_MODE: u32 = 0o600;


/// The bytes an old file may still hold unread when a rotation is followed; over it the switch happens and the bytes are named.
pub const MAX_ROTATED_BACKLOG_BYTES: u64 = 1_073_741_824;


/// The work of one pass over a handle; `pending` and `skipped` are the bytes of the unterminated line after `consumed`.
#[derive(Debug, Default)]
pub struct Pass {
    pub lines: Vec<String>,
    pub malformed: u64,
    pub consumed: u64,
    pub complete: usize,
    pub tail: Vec<u8>,
    pub pending: Vec<u8>,
    pub skipped: usize,
    pub done: bool,
    pub eof: bool,
}


/// One drained handle: the lines read, the follower after them and whether the end of the file was reached with budget left.
#[derive(Debug)]
pub struct Drained {
    pub lines: Vec<String>,
    pub follower: Follower,
    pub counts: FollowCounts,
    pub complete: usize,
    pub eof: bool,
    pub partial: bool,
}


/// The lowercase hex SHA-256 of `bytes`.
pub fn digest_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}


/// Exactly `len` bytes at `start`, or `None` when the file is shorter.
pub fn read_range(file: &File, start: u64, len: usize) -> io::Result<Option<Vec<u8>>> {
    let mut buffer = vec![0; len];
    match file.read_exact_at(&mut buffer, start) {
        Ok(()) => Ok(Some(buffer)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}


/// The bytes just before `offset` still hash to `expected`; a shorter file never matches.
pub fn tail_matches(file: &File, offset: u64, tail_len: usize, expected: &str) -> io::Result<bool> {
    let start = offset.saturating_sub(tail_len as u64);
    Ok(read_range(file, start, tail_len)?.is_some_and(|bytes| digest_hex(&bytes) == expected))
}


/// Opens `eve.json` without following a symlink and judges it on the handle; an absent file is `None`.
pub fn open_eve(path: &Path) -> Result<Option<File>, NdrError> {
    match rustix::fs::open(path, FILE_FLAGS, Mode::empty()) {
        Ok(handle) => regular(File::from(handle)).map(Some),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP | Errno::NXIO) => Err(NdrError::EveNotRegular),
        Err(errno) => Err(NdrError::Eve(io::Error::from(errno))),
    }
}


fn regular(file: File) -> Result<File, NdrError> {
    let meta = file.metadata()?;
    match (meta.is_file(), meta.nlink() > 1) {
        (false, _) => Err(NdrError::EveNotRegular),
        (true, true) => Err(NdrError::EveShared),
        (true, false) => Ok(file),
    }
}


/// A follower at the start of `file`.
pub fn follower_at_start(file: File) -> io::Result<Follower> {
    follower_on(Arc::new(file))
}


/// A follower at the start of a handle that may already be shared.
pub fn follower_on(file: Arc<File>) -> io::Result<Follower> {
    let meta = file.metadata()?;
    Ok(Follower {
        file,
        inode: meta.ino(),
        device: meta.dev(),
        offset: 0,
        tail_len: 0,
        tail_sha256: digest_hex(&[]),
        skip: 0,
        next: None,
        next_inode: 0,
        seen_inode: 0,
        seen_len: 0,
    })
}


/// A cursor is possible: the head covers the first bytes up to the bound, the tail lies inside the consumed bytes and inside the line bound.
pub fn cursor_is_valid(cursor: &Cursor, limits: &Limits) -> bool {
    cursor.head_len as u64 == cursor.offset.min(HEAD_BYTES as u64)
        && cursor.tail_len as u64 <= cursor.offset
        && cursor.tail_len <= limits.max_line_bytes
        && (cursor.offset > 0) == (cursor.tail_len > 0)
}


/// Opens `eve.json` and places the follower: from the saved cursor when the bytes it fingerprints are still there, else from 0 with the gap counted.
pub fn resume(path: &Path, saved: Option<&Cursor>, limits: &Limits) -> Result<(Follower, FollowCounts), NdrError> {
    let file = open_eve(path)?.ok_or(NdrError::EveMissing)?;
    let meta = file.metadata()?;
    let fresh = follower_at_start(file)?;
    match saved {
        None => Ok((fresh, FollowCounts::default())),
        Some(cursor) if !cursor_is_valid(cursor, limits) => Err(NdrError::CursorInvalid),
        Some(cursor) if cursor.inode != meta.ino() => {
            tracing::warn!("eve.json changed identity while down, reading the new file from the start");
            Ok((
                fresh,
                FollowCounts {
                    rotated_while_down: 1,
                    ..FollowCounts::default()
                },
            ))
        }
        Some(cursor) => verify_cursor(fresh, cursor, meta.dev()),
    }
}


fn verify_cursor(fresh: Follower, cursor: &Cursor, device: u64) -> Result<(Follower, FollowCounts), NdrError> {
    let head_ok = tail_matches(&fresh.file, cursor.head_len as u64, cursor.head_len, &cursor.head_sha256)?;
    let tail_ok = tail_matches(&fresh.file, cursor.offset, cursor.tail_len, &cursor.tail_sha256)?;
    let mut counts = FollowCounts {
        device_changed: u64::from(cursor.device != device),
        ..FollowCounts::default()
    };
    match head_ok && tail_ok {
        true => Ok((
            Follower {
                offset: cursor.offset,
                tail_len: cursor.tail_len,
                tail_sha256: cursor.tail_sha256.clone(),
                ..fresh
            },
            counts,
        )),
        false => {
            tracing::warn!("eve.json does not match the saved fingerprints, reading it from the start");
            counts.eve_truncated = 1;
            Ok((fresh, counts))
        }
    }
}


/// The cursor to persist for a follower: identity, offset and the fingerprints re-read through the held handle.
pub fn cursor_of(follower: &Follower) -> io::Result<Cursor> {
    let head_len = follower.offset.min(HEAD_BYTES as u64) as usize;
    let head = read_range(&follower.file, 0, head_len)?.ok_or(io::ErrorKind::UnexpectedEof)?;
    Ok(Cursor {
        inode: follower.inode,
        device: follower.device,
        head_len,
        head_sha256: digest_hex(&head),
        offset: follower.offset,
        tail_len: follower.tail_len,
        tail_sha256: follower.tail_sha256.clone(),
    })
}


/// Keeps the last `max_bytes` bytes of the line and its newline.
pub fn line_tail(pending: &[u8], body: &[u8], max_bytes: usize) -> Vec<u8> {
    let mut joined = [pending, body, b"\n"].concat();
    let start = joined.len().saturating_sub(max_bytes);
    joined.split_off(start)
}


/// Adds the bytes of an unterminated line, or drops them and remembers their count once the line is over the bound.
pub fn extend_partial(pass: &mut Pass, segment: &[u8], limits: &Limits) {
    let total = pass.pending.len() + segment.len();
    if total > limits.max_line_bytes {
        pass.skipped += total;
        pass.pending.clear();
    } else {
        pass.pending.extend_from_slice(segment);
    }
}


/// Completes a line: a line over the bound or not UTF-8 is counted `malformed`, never returned.
pub fn complete_line(pass: &mut Pass, body: &[u8], limits: &Limits) {
    let content = pass.pending.len() + body.len();
    let over = pass.skipped > 0 || content > limits.max_line_bytes;
    match over {
        true => pass.malformed += 1,
        false => match String::from_utf8([pass.pending.as_slice(), body].concat()) {
            Ok(line) => pass.lines.push(line),
            Err(_) => pass.malformed += 1,
        },
    }
    pass.tail = line_tail(&pass.pending, body, limits.max_line_bytes);
    pass.consumed += (pass.skipped + content + 1) as u64;
    pass.complete += 1;
    pass.pending.clear();
    pass.skipped = 0;
}


/// One segment of a chunk, up to and including a newline or the rest of the chunk; stops once the line budget is spent.
pub fn absorb(pass: &mut Pass, segment: &[u8], limits: &Limits, budget: usize) -> ControlFlow<()> {
    match segment.strip_suffix(b"\n") {
        None => {
            extend_partial(pass, segment, limits);
            ControlFlow::Continue(())
        }
        Some(_) if pass.complete >= budget => {
            pass.done = true;
            ControlFlow::Break(())
        }
        Some(body) => {
            complete_line(pass, body, limits);
            ControlFlow::Continue(())
        }
    }
}


/// Reads one chunk after the bytes already seen and absorbs it; the end of the file ends the pass.
pub fn read_step(file: &File, start: u64, mut pass: Pass, limits: &Limits, budget: usize) -> io::Result<Pass> {
    match pass.done {
        true => Ok(pass),
        false => {
            let mut chunk = vec![0; CHUNK_BYTES];
            let seen = pass.consumed + (pass.pending.len() + pass.skipped) as u64;
            let count = file.read_at(&mut chunk, start + seen)?;
            chunk.truncate(count);
            pass.done = count == 0;
            pass.eof = count == 0;
            let _flow = chunk
                .split_inclusive(|byte| *byte == b'\n')
                .try_for_each(|segment| absorb(&mut pass, segment, limits, budget));
            Ok(pass)
        }
    }
}


/// The bytes of an over-long line seen but not ended: the next pass starts after them, so a tick always moves forward.
pub fn carried_skip(pass: &Pass) -> u64 {
    match pass.skipped {
        0 => 0,
        skipped => (skipped + pass.pending.len()) as u64,
    }
}


/// Checks the held handle still holds the consumed bytes (a copytruncate rewinds it), then reads lines to the end or to the budget.
pub fn drain(follower: &Follower, budget: usize, limits: &Limits) -> io::Result<Drained> {
    let within = follower.offset + follower.skip <= follower.file.metadata()?.len();
    let intact = within && tail_matches(&follower.file, follower.offset, follower.tail_len, &follower.tail_sha256)?;
    let base = match intact {
        true => follower.clone(),
        false => {
            tracing::warn!("eve.json was truncated, reading it from the start");
            Follower {
                offset: 0,
                tail_len: 0,
                tail_sha256: digest_hex(&[]),
                skip: 0,
                ..follower.clone()
            }
        }
    };
    let first_pass = Pass {
        skipped: base.skip as usize,
        ..Pass::default()
    };
    let pass = (0..MAX_CHUNKS).try_fold(first_pass, |state, _| read_step(&base.file, base.offset, state, limits, budget))?;
    let (tail_len, tail_sha256) = match pass.complete {
        0 => (base.tail_len, base.tail_sha256.clone()),
        _ => (pass.tail.len(), digest_hex(&pass.tail)),
    };
    Ok(Drained {
        follower: Follower {
            offset: base.offset + pass.consumed,
            tail_len,
            tail_sha256,
            skip: carried_skip(&pass),
            ..base
        },
        lines: pass.lines,
        counts: FollowCounts {
            malformed: pass.malformed,
            eve_truncated: u64::from(!intact),
            ..FollowCounts::default()
        },
        complete: pass.complete,
        eof: pass.eof,
        partial: pass.pending.len() + pass.skipped > 0,
    })
}


/// Appends `later` to `earlier`; the follower, the end-of-file flag and the partial flag are the later ones.
pub fn merge(earlier: Drained, later: Drained) -> Drained {
    Drained {
        lines: [earlier.lines, later.lines].concat(),
        follower: later.follower,
        counts: FollowCounts {
            malformed: earlier.counts.malformed + later.counts.malformed,
            eve_truncated: earlier.counts.eve_truncated + later.counts.eve_truncated,
            rotations: earlier.counts.rotations + later.counts.rotations,
            rotated_unread_bytes: earlier.counts.rotated_unread_bytes + later.counts.rotated_unread_bytes,
            successors_missed: earlier.counts.successors_missed + later.counts.successors_missed,
            missed_bytes: earlier.counts.missed_bytes + later.counts.missed_bytes,
            successors_refused: earlier.counts.successors_refused + later.counts.successors_refused,
            ..FollowCounts::default()
        },
        complete: earlier.complete + later.complete,
        eof: later.eof,
        partial: later.partial,
    }
}


/// The bytes of the held file that nobody read: the file length after the offset and the skipped bytes.
pub fn unread_bytes(follower: &Follower) -> io::Result<u64> {
    Ok(follower.file.metadata()?.len().saturating_sub(follower.offset + follower.skip))
}


/// The old file is drained a last time and the new one read from its start once the old one is at its end or holds more than `max_backlog` unread.
pub fn switch(first: Drained, next: Arc<File>, limits: &Limits, max_backlog: u64) -> io::Result<Drained> {
    let last = drain(&first.follower, limits.max_lines_per_tick.saturating_sub(first.complete), limits)?;
    let old = merge(first, last);
    let unread = unread_bytes(&old.follower)?;
    match (old.eof, unread > max_backlog) {
        (false, false) => Ok(old),
        (reached, _) => {
            let fresh = Follower {
                seen_inode: old.follower.seen_inode,
                seen_len: old.follower.seen_len,
                ..follower_on(next)?
            };
            let remaining = limits.max_lines_per_tick.saturating_sub(old.complete);
            let rest = drain(&fresh, remaining, limits)?;
            let closing = Drained {
                counts: FollowCounts {
                    malformed: old.counts.malformed + u64::from(reached && old.partial),
                    rotations: old.counts.rotations + 1,
                    rotated_unread_bytes: old.counts.rotated_unread_bytes + unread * u64::from(!reached),
                    ..old.counts
                },
                ..old
            };
            Ok(merge(closing, rest))
        }
    }
}


/// The errno of an open failure, or 0 for a refusal that carries none.
pub fn refusal_errno(error: &NdrError) -> i32 {
    match error {
        NdrError::Eve(source) => source.raw_os_error().unwrap_or(0),
        _ => 0,
    }
}


/// The path as seen this tick: any open failure is no candidate, counted and logged with its errno; the held file keeps draining.
pub fn candidate_with(path: &Path, open: OpenEveFn) -> (Option<File>, u64) {
    match open(path) {
        Ok(found) => (found, 0),
        Err(error) => {
            let errno = refusal_errno(&error);
            tracing::warn!(errno, "a successor eve.json is refused, the held file keeps draining");
            (None, 1)
        }
    }
}


/// Holds the first successor once it holds bytes; a newer file seen while another waits is remembered, and the one it replaces is counted as passed over.
pub fn observe(follower: Follower, candidate: Option<File>) -> io::Result<(Follower, FollowCounts)> {
    match candidate {
        None => Ok((follower, FollowCounts::default())),
        Some(file) => {
            let meta = file.metadata()?;
            let is_held = follower.next.is_some() && follower.next_inode == meta.ino();
            match (meta.ino() == follower.inode || is_held, follower.next.is_none() && meta.len() > 0) {
                (true, _) => Ok((follower, FollowCounts::default())),
                (false, true) => Ok(hold(follower, file, meta.ino())),
                (false, false) => Ok(passed_over(follower, meta.ino(), meta.len())),
            }
        }
    }
}


fn missed_of(follower: &Follower, inode: u64) -> FollowCounts {
    let missed = follower.seen_inode != 0 && follower.seen_inode != inode;
    if missed {
        tracing::warn!("eve.json changed again before a successor was read, a middle file is not kept");
    }
    FollowCounts {
        successors_missed: u64::from(missed),
        missed_bytes: follower.seen_len * u64::from(missed),
        ..FollowCounts::default()
    }
}


fn hold(follower: Follower, file: File, inode: u64) -> (Follower, FollowCounts) {
    let counts = missed_of(&follower, inode);
    let held = Follower {
        next: Some(Arc::new(file)),
        next_inode: inode,
        seen_inode: 0,
        seen_len: 0,
        ..follower
    };
    (held, counts)
}


fn passed_over(follower: Follower, inode: u64, len: u64) -> (Follower, FollowCounts) {
    let counts = missed_of(&follower, inode);
    let seen = Follower {
        seen_inode: inode,
        seen_len: len,
        ..follower
    };
    (seen, counts)
}


/// One tick: drains the held handle, holds the first successor seen and switches to that handle, never to whatever the path holds then.
pub fn follow_tick(path: &Path, follower: &Follower, limits: &Limits) -> Result<Ticked, NdrError> {
    follow_tick_with(path, follower, limits, open_eve)
}


/// `follow_tick` with the open of the path injected.
pub fn follow_tick_with(path: &Path, follower: &Follower, limits: &Limits, open: OpenEveFn) -> Result<Ticked, NdrError> {
    let drained = drain(follower, limits.max_lines_per_tick, limits)?;
    let (candidate, refused) = candidate_with(path, open);
    let (watched, seen) = observe(drained.follower.clone(), candidate)?;
    let first = Drained {
        follower: watched,
        ..drained
    };
    let mut done = match first.follower.next.clone() {
        None => first,
        Some(next) => switch(first, next, limits, MAX_ROTATED_BACKLOG_BYTES)?,
    };
    done.counts.successors_missed += seen.successors_missed;
    done.counts.missed_bytes += seen.missed_bytes;
    done.counts.successors_refused += refused;
    let skipping_bytes = done.follower.skip;
    Ok(Ticked {
        lines: done.lines,
        follower: done.follower,
        counts: done.counts,
        skipping_bytes,
    })
}


/// Opens the directory that holds the state file, owned by the effective user and closed to group and others.
pub fn open_state_dir(path: &Path) -> Result<OwnedFd, NdrError> {
    open_trusted_dir(path, geteuid().as_raw()).map_err(NdrError::WorkDir)
}


/// Reads the saved cursor: no file is `None`; a symlink, a non-regular file, a file over the cap or bad JSON is a named error, never a reset.
pub fn load_state(dir: &OwnedFd, name: &str) -> Result<Option<Cursor>, NdrError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    match openat(dir, name, flags, Mode::empty()) {
        Ok(handle) => parse_state(File::from(handle)).map(Some),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Err(NdrError::StateNotRegular),
        Err(errno) => Err(NdrError::State(io::Error::from(errno))),
    }
}


fn parse_state(file: File) -> Result<Cursor, NdrError> {
    let is_file = file.metadata().map_err(NdrError::State)?.is_file();
    let mut bytes = Vec::new();
    is_file.then_some(()).ok_or(NdrError::StateNotRegular)?;
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes).map_err(NdrError::State)?;
    (bytes.len() as u64 <= MAX_STATE_BYTES)
        .then_some(())
        .ok_or(NdrError::StateTooLarge { max_bytes: MAX_STATE_BYTES })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        let kind = error.classify();
        tracing::warn!(kind = ?kind, "the follower state is not valid");
        NdrError::StateMalformed
    })
}


fn write_state(dir: &OwnedFd, temporary: &str, name: &str, bytes: &[u8]) -> io::Result<()> {
    match unlinkat(dir, temporary, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(io::Error::from(errno)),
    }?;
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = File::from(openat(dir, temporary, flags, Mode::from_raw_mode(STATE_MODE))?);
    file.write_all(bytes)?;
    file.sync_all()?;
    renameat(dir, temporary, dir, name)?;
    File::from(dir.try_clone()?).sync_all()
}


/// Writes the cursor to a temporary file, syncs it, renames it over `name` and syncs the directory, all relative to the opened directory.
pub fn store_state(dir: &OwnedFd, temporary: &str, name: &str, cursor: &Cursor) -> Result<(), NdrError> {
    let bytes = serde_json::to_vec(cursor).map_err(io::Error::from).map_err(NdrError::State)?;
    write_state(dir, temporary, name, &bytes).map_err(NdrError::State)
}
