use crate::error::ListError;
use crate::model::{BreachedList, FileIdentity, ListInfo, Located, NtHash, Probed, Verdict, CHECK_SAMPLES, HALVES, MAX_PROBES, WINDOW_BYTES};
use crate::parse::locate;
use crate::types::{InspectFn, ReadAtFn};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
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


#[cfg(not(unix))]
pub fn open_options() -> OpenOptions {
    OpenOptions::new().read(true).clone()
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


/// Opens the list once without following a symlink, judges the handle (a regular file) and records its size.
pub fn open_list_with(path: &Path, inspect: InspectFn) -> Result<BreachedList, ListError> {
    let name = path.display().to_string();
    let file = open_options().open(path).map_err(|source| open_error(name.clone(), source))?;
    let metadata = inspect(&file).map_err(|source| ListError::Open { file: name.clone(), source })?;
    if metadata.is_file() {
        Ok(BreachedList {
            file,
            size: metadata.len(),
            identity: identity_of(&metadata),
        })
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


/// A bounded sample of `CHECK_SAMPLES` evenly spaced lines must be in order, else the search would lie.
pub fn check_order_with(list: &BreachedList, read: ReadAtFn) -> Result<ListInfo, ListError> {
    let step = list.size / CHECK_SAMPLES;
    let (_, lines_checked) = (0..CHECK_SAMPLES).try_fold((None::<NtHash>, 0u64), |(previous, lines), index| {
        let offset = step * index;
        match fetch(list, read, offset, offset == 0)? {
            Located::Missing => Ok((previous, lines)),
            Located::Line(entry) => {
                let out_of_order = previous.as_ref().is_some_and(|earlier| earlier.0.as_slice() > entry.hash.0.as_slice());
                if out_of_order {
                    Err(ListError::Unsorted { offset: entry.start })
                } else {
                    Ok((Some(entry.hash), lines + 1))
                }
            }
        }
    })?;
    if lines_checked == 0 {
        Err(ListError::NoLines)
    } else {
        Ok(ListInfo {
            bytes: list.size,
            lines_checked,
        })
    }
}


/// `check_order_with` over the real file.
pub fn check_order(list: &BreachedList) -> Result<ListInfo, ListError> {
    check_order_with(list, read_at)
}
