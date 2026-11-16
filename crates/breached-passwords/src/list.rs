use crate::error::ListError;
use crate::model::{BreachedList, ListInfo, Located, NtHash, Probed, Verdict, CHECK_SAMPLES, HALVES, MAX_PROBES, WINDOW_BYTES};
use crate::parse::locate;
use crate::types::{InspectFn, ReadAtFn};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use zeroize::Zeroizing;


/// The next step of a search: found with a count, or the new upper or lower bound.
pub enum Move {
    Found(u64),
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
        Ok(BreachedList { file, size: metadata.len() })
    } else {
        Err(ListError::NotRegular { file: name })
    }
}


/// The list at `path`, opened through the real metadata call.
pub fn open_list(path: &Path) -> Result<BreachedList, ListError> {
    open_list_with(path, handle_metadata)
}


/// One seek and one bounded read of `WINDOW_BYTES` at `offset`; the bytes are zeroed on drop.
pub fn read_at(file: &File, offset: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut reader = file;
    reader.seek(SeekFrom::Start(offset))?;
    let mut window = Zeroizing::new(Vec::new());
    reader.take(WINDOW_BYTES).read_to_end(&mut window)?;
    Ok(window)
}


/// The first line starting at `offset` (`aligned`, the offset is a line start) or after it.
pub fn fetch(list: &BreachedList, read: ReadAtFn, offset: u64, aligned: bool) -> Result<Located, ListError> {
    let read_offset = if aligned { offset } else { offset.saturating_sub(1) };
    let window = read(&list.file, read_offset).map_err(|source| ListError::Read { offset: read_offset, source })?;
    let at_eof = (window.len() as u64) < WINDOW_BYTES;
    locate(&window, read_offset, aligned, at_eof)
}


/// One probe at the middle of the candidate range `[lo, hi)`.
pub fn advance(list: &BreachedList, read: ReadAtFn, target: &NtHash, lo: u64, hi: u64) -> Result<Move, ListError> {
    let mid = lo + (hi - lo) / HALVES;
    let located = fetch(list, read, mid, mid == lo)?;
    Ok(match located {
        Located::Line(entry) if entry.start < hi => match entry.hash.0.as_slice().cmp(target.0.as_slice()) {
            std::cmp::Ordering::Equal => Move::Found(entry.count),
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
    let mut found: Option<u64> = None;
    let mut probes = 0;
    while found.is_none() && lo < hi && probes < max_probes.min(MAX_PROBES) {
        match advance(list, read, target, lo, hi)? {
            Move::Found(count) => found = Some(count),
            Move::Below(bound) => hi = bound,
            Move::Above(bound) => lo = bound,
        }
        probes += 1;
    }
    if found.is_none() && lo < hi {
        Err(ListError::ProbeLimit)
    } else {
        let count = found.unwrap_or(0);
        Ok(Probed {
            verdict: Verdict {
                compromised: found.is_some(),
                count,
            },
            probes,
        })
    }
}


/// The verdict for one hash and the seeks it took.
pub fn lookup_probed(list: &BreachedList, target: &NtHash) -> Result<Probed, ListError> {
    lookup_with(list, target, MAX_PROBES, read_at)
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
    Ok(ListInfo {
        bytes: list.size,
        lines_checked,
    })
}


/// `check_order_with` over the real file.
pub fn check_order(list: &BreachedList) -> Result<ListInfo, ListError> {
    check_order_with(list, read_at)
}
