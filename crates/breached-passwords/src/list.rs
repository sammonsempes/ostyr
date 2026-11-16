use crate::error::ListError;
use crate::model::{
    BreachedList, FileIdentity, Located, NtHash, Probed, Scanned, Verdict, HALVES, MAX_LINE_BYTES, MAX_LIST_LINES, MAX_PROBES, SCAN_BUFFER_BYTES,
    WINDOW_BYTES, WRITE_BITS,
};
use crate::parse::{locate, parse_line};
use crate::types::{InspectFn, ReadAtFn};
use core_config::secret_file::judge_secret;
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use zeroize::Zeroizing;


/// The next step of a search: found with a count, or the new upper or lower bound.
pub enum Move {
    Found,
    Below(u64),
    Above(u64),
}


#[cfg(unix)]
pub fn open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).clone()
}


/// Windows: shared for reading only, so no writer can open the list while it is open.
#[cfg(not(unix))]
pub fn open_options() -> OpenOptions {
    use crate::model::FILE_SHARE_READ;
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).clone()
}


/// An open that failed on a symlink (`ELOOP` under `O_NOFOLLOW`) is `Symlink`, anything else keeps its cause.
#[cfg(unix)]
pub fn open_error(file: String, source: io::Error) -> ListError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        ListError::Symlink { file }
    } else {
        ListError::Open { file, source }
    }
}


#[cfg(not(unix))]
pub fn open_error(file: String, source: io::Error) -> ListError {
    ListError::Open { file, source }
}


/// The identity of a handle's metadata. The change time cannot be set back from userland, so a rewrite with a restored write time still differs.
#[cfg(unix)]
pub fn identity_of(metadata: &Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        written: metadata.mtime(),
        written_nsec: metadata.mtime_nsec(),
        changed: metadata.ctime(),
        changed_nsec: metadata.ctime_nsec(),
    }
}


/// Windows has no inode or change time here: size, write time and creation time.
#[cfg(not(unix))]
pub fn identity_of(metadata: &Metadata) -> FileIdentity {
    use std::os::windows::fs::MetadataExt;
    FileIdentity {
        device: 0,
        inode: 0,
        size: metadata.file_size(),
        written: metadata.last_write_time() as i64,
        written_nsec: 0,
        changed: metadata.creation_time() as i64,
        changed_nsec: 0,
    }
}


/// The metadata of the opened handle.
pub fn handle_metadata(handle: &File) -> io::Result<Metadata> {
    handle.metadata()
}


/// The owner and mode rule of the secret files, reused: owned by the process user or root, no group or other write bit (the list stays readable).
pub fn judge_list(file: &str, mode: u32, owner: u32, process_user: u32) -> Result<(), ListError> {
    judge_secret(file, true, mode & WRITE_BITS, owner, process_user).map_err(ListError::Untrusted)
}


/// `judge_list` on the opened handle's metadata.
#[cfg(unix)]
pub fn judge_owner(file: &str, metadata: &Metadata) -> Result<(), ListError> {
    use std::os::unix::fs::MetadataExt;
    judge_list(file, metadata.mode(), metadata.uid(), rustix::process::geteuid().as_raw())
}


/// Windows has no owner or mode here.
#[cfg(not(unix))]
pub fn judge_owner(_file: &str, _metadata: &Metadata) -> Result<(), ListError> {
    Ok(())
}


/// One line read with its newline: the hash, strictly above `previous`; a line over the cap, without its newline, or out of order is refused.
pub fn read_entry(line: &[u8], previous: Option<&NtHash>, start: u64) -> Result<NtHash, ListError> {
    match line.split_last() {
        None => Err(ListError::Changed),
        Some((b'\n', body)) => {
            let hash = parse_line(body)?;
            if previous.is_some_and(|earlier| earlier.0.as_slice() >= hash.0.as_slice()) {
                Err(ListError::Unsorted { offset: start })
            } else {
                Ok(hash)
            }
        }
        Some(_) if line.len() > MAX_LINE_BYTES => Err(ListError::LineTooLong),
        Some(_) => Err(ListError::Unterminated),
    }
}


/// One sequential pass over the first `size` bytes, at most `max_lines` lines: every line is checked (format, terminator, strictly ascending) and the SHA-256 is computed.
pub fn scan(reader: &mut dyn Read, size: u64, max_lines: u64) -> Result<Scanned, ListError> {
    let mut input = BufReader::with_capacity(SCAN_BUFFER_BYTES, reader.take(size));
    let mut hasher = Sha256::new();
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE_BYTES + 1));
    let mut previous: Option<NtHash> = None;
    let mut lines = 0u64;
    let mut consumed = 0u64;
    while consumed < size && lines < max_lines.min(MAX_LIST_LINES) {
        line.clear();
        let read = (&mut input)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|source| ListError::Read { source })?;
        previous = Some(read_entry(&line, previous.as_ref(), consumed)?);
        hasher.update(line.as_slice());
        consumed += read as u64;
        lines += 1;
    }
    if lines == 0 {
        Err(ListError::NoLines)
    } else if consumed < size {
        Err(ListError::TooManyLines)
    } else {
        Ok(Scanned {
            lines,
            sha256: HEXLOWER.encode(hasher.finalize().as_slice()),
        })
    }
}


/// Opens the list once without following a symlink, judges the handle (a regular file, owned, not writable by others), checks it whole and records it.
pub fn open_list_with(path: &Path, inspect: InspectFn) -> Result<BreachedList, ListError> {
    let name = path.display().to_string();
    let file = open_options().open(path).map_err(|source| open_error(name.clone(), source))?;
    let metadata = inspect(&file).map_err(|source| ListError::Open { file: name.clone(), source })?;
    if metadata.is_file() {
        judge_owner(&name, &metadata)?;
        let mut reader = &file;
        let scanned = scan(&mut reader, metadata.len(), MAX_LIST_LINES)?;
        let list = BreachedList {
            file,
            size: metadata.len(),
            identity: identity_of(&metadata),
            lines: scanned.lines,
            sha256: scanned.sha256,
        };
        verify_unchanged_with(&list, inspect).map(|()| list)
    } else {
        Err(ListError::NotRegular { file: name })
    }
}


/// The list at `path`, opened through the real metadata call.
pub fn open_list(path: &Path) -> Result<BreachedList, ListError> {
    open_list_with(path, handle_metadata)
}


/// One seek and one bounded read of `WINDOW_BYTES` at `offset` into a buffer allocated once; the bytes are zeroed on drop.
pub fn read_at(file: &File, offset: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut reader = file;
    reader.seek(SeekFrom::Start(offset))?;
    let mut window = Zeroizing::new(Vec::with_capacity(WINDOW_BYTES as usize));
    reader.take(WINDOW_BYTES).read_to_end(&mut window)?;
    Ok(window)
}


/// The first line starting at `offset` (`aligned`, the offset is a line start) or after it.
pub fn fetch(list: &BreachedList, read: ReadAtFn, offset: u64, aligned: bool) -> Result<Located, ListError> {
    let read_offset = if aligned { offset } else { offset.saturating_sub(1) };
    let mut window = read(&list.file, read_offset).map_err(|source| ListError::Read { source })?;
    let expected = list.size.saturating_sub(read_offset).min(WINDOW_BYTES);
    if (window.len() as u64) < expected {
        Err(ListError::Changed)
    } else {
        window.truncate(expected as usize);
        locate(&window, read_offset, aligned, read_offset + expected >= list.size)
    }
}


/// One probe at the middle of the candidate range `[lo, hi)`.
pub fn advance(list: &BreachedList, read: ReadAtFn, target: &NtHash, lo: u64, hi: u64) -> Result<Move, ListError> {
    let mid = lo + (hi - lo) / HALVES;
    let located = fetch(list, read, mid, mid == lo)?;
    Ok(match located {
        Located::Line(entry) if entry.start < hi => match entry.hash.0.as_slice().cmp(target.0.as_slice()) {
            std::cmp::Ordering::Equal => Move::Found,
            std::cmp::Ordering::Less => Move::Above(entry.next),
            std::cmp::Ordering::Greater => Move::Below(mid),
        },
        _ => Move::Below(mid),
    })
}


/// Binary search over byte offsets with at most `max_probes` seeks, reading through `read`.
pub fn lookup_with(list: &BreachedList, target: &NtHash, max_probes: u32, read: ReadAtFn) -> Result<Probed, ListError> {
    let mut lo = 0;
    let mut hi = list.size;
    let mut found = false;
    let mut probes = 0;
    while !found && lo < hi && probes < max_probes.min(MAX_PROBES) {
        match advance(list, read, target, lo, hi)? {
            Move::Found => found = true,
            Move::Below(bound) => hi = bound,
            Move::Above(bound) => lo = bound,
        }
        probes += 1;
    }
    if !found && lo < hi {
        Err(ListError::ProbeLimit)
    } else {
        Ok(Probed {
            verdict: Verdict { compromised: found },
            probes,
        })
    }
}


/// Fails with `Changed` when a fresh `fstat` of the same handle differs from the identity recorded at open.
pub fn verify_unchanged_with(list: &BreachedList, inspect: InspectFn) -> Result<(), ListError> {
    let metadata = inspect(&list.file).map_err(|source| ListError::Read { source })?;
    if identity_of(&metadata) == list.identity {
        Ok(())
    } else {
        Err(ListError::Changed)
    }
}


/// `verify_unchanged_with` through the real metadata call.
pub fn verify_unchanged(list: &BreachedList) -> Result<(), ListError> {
    verify_unchanged_with(list, handle_metadata)
}


/// The verdict for one hash and the seeks it took; a list changed since the open is `Changed`, never a verdict.
pub fn lookup_probed(list: &BreachedList, target: &NtHash) -> Result<Probed, ListError> {
    let probed = lookup_with(list, target, MAX_PROBES, read_at)?;
    verify_unchanged(list).map(|()| probed)
}


/// The verdict for one hash.
pub fn lookup(list: &BreachedList, target: &NtHash) -> Result<Verdict, ListError> {
    lookup_probed(list, target).map(|probed| probed.verdict)
}


/// One verdict per hash, in input order.
pub fn lookup_many(list: &BreachedList, targets: &[NtHash]) -> Result<Vec<Verdict>, ListError> {
    targets.iter().map(|target| lookup(list, target)).collect()
}
