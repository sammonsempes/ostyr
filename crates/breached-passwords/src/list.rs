use crate::error::ListError;
use crate::model::{BreachedList, FileIdentity, NtHash, Scanned, Verdict, MAX_LINE_BYTES, MAX_LIST_LINES, SCAN_BUFFER_BYTES, WRITE_BITS};
use crate::parse::parse_line;
use crate::types::InspectFn;
use core_config::secret_file::judge_secret;
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use zeroize::Zeroizing;


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


/// The owner rule of the secret files, reused, then a list wording for a group or other write bit (the list stays readable).
pub fn judge_list(file: &str, mode: u32, owner: u32, process_user: u32) -> Result<(), ListError> {
    judge_secret(file, true, 0, owner, process_user).map_err(|source| ListError::ForeignOwner {
        file: file.to_owned(),
        source,
    })?;
    if mode & WRITE_BITS == 0 {
        Ok(())
    } else {
        Err(ListError::Writable { file: file.to_owned() })
    }
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


/// The targets sorted and deduplicated: the keys the pass joins the list against.
pub fn sorted_keys(targets: &[NtHash]) -> Vec<NtHash> {
    let mut keys = targets.to_vec();
    keys.sort_unstable_by(|left, right| left.0.as_slice().cmp(right.0.as_slice()));
    keys.dedup_by(|left, right| left.0.as_slice() == right.0.as_slice());
    keys
}


/// The position of `hash` among the sorted `keys`, or where it would sit.
pub fn key_position(keys: &[NtHash], hash: &NtHash) -> Result<usize, usize> {
    keys.binary_search_by(|key| key.0.as_slice().cmp(hash.0.as_slice()))
}


/// Sets the flag of `hash` when it is one of the sorted `keys`; every line costs the same search.
pub fn mark(keys: &[NtHash], found: &mut [bool], hash: &NtHash) {
    if let Ok(index) = key_position(keys, hash) {
        found.get_mut(index).into_iter().for_each(|flag| *flag = true);
    }
}


/// One sequential pass: every line is checked (format, terminator, order), hashed and joined against the sorted `keys`; no seek, no early stop.
pub fn scan(reader: &mut dyn Read, size: u64, max_lines: u64, keys: &[NtHash]) -> Result<Scanned, ListError> {
    let mut input = BufReader::with_capacity(SCAN_BUFFER_BYTES, reader.take(size));
    let mut hasher = Sha256::new();
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE_BYTES + 1));
    let mut previous: Option<NtHash> = None;
    let mut found = vec![false; keys.len()];
    let mut lines = 0u64;
    let mut consumed = 0u64;
    while consumed < size && lines < max_lines.min(MAX_LIST_LINES) {
        line.clear();
        let read = (&mut input)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|source| ListError::Read { source })?;
        let hash = read_entry(&line, previous.as_ref(), consumed)?;
        mark(keys, &mut found, &hash);
        previous = Some(hash);
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
            found,
        })
    }
}


/// One verdict per target, in input order, from the flags of the sorted `keys`.
pub fn verdicts_of(targets: &[NtHash], keys: &[NtHash], found: &[bool]) -> Vec<Verdict> {
    targets
        .iter()
        .map(|target| {
            let (Ok(index) | Err(index)) = key_position(keys, target);
            Verdict {
                compromised: found.get(index).is_some_and(|flag| *flag),
            }
        })
        .collect()
}


/// Opens the list once, judges the handle, checks it whole while joining it against `targets`; verdicts exist only after a clean pass.
pub fn open_list_with(path: &Path, targets: &[NtHash], inspect: InspectFn) -> Result<BreachedList, ListError> {
    let name = path.display().to_string();
    let file = open_options().open(path).map_err(|source| open_error(name.clone(), source))?;
    let metadata = inspect(&file).map_err(|source| ListError::Open { file: name.clone(), source })?;
    if metadata.is_file() {
        judge_owner(&name, &metadata)?;
        let keys = sorted_keys(targets);
        let mut reader = &file;
        let scanned = scan(&mut reader, metadata.len(), MAX_LIST_LINES, &keys)?;
        let list = BreachedList {
            file,
            size: metadata.len(),
            identity: identity_of(&metadata),
            lines: scanned.lines,
            sha256: scanned.sha256,
            verdicts: verdicts_of(targets, &keys, &scanned.found),
        };
        verify_unchanged_with(&list, inspect).map(|()| list)
    } else {
        Err(ListError::NotRegular { file: name })
    }
}


/// The list at `path`, opened through the real metadata call.
pub fn open_list(path: &Path, targets: &[NtHash]) -> Result<BreachedList, ListError> {
    open_list_with(path, targets, handle_metadata)
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
