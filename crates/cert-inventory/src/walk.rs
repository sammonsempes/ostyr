//! Unix directory walk by file descriptor: every directory and file is opened relative to its parent's handle, never by path text.

use crate::scan::{cut_path, examine, has_wanted_extension, load_handle, record_error, Loaded, ScanSettings, ScanState};
use rustix::fs::{openat, statat, AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::ops::ControlFlow;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};


const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);


/// One open directory of the walk stack; the stack never holds more than `max_depth` of them.
pub struct Level {
    pub handle: OwnedFd,
    pub dir: Dir,
    pub path: PathBuf,
}


/// One directory entry as listed: its name and the type the directory reported (which may be `Unknown`).
pub struct Listed {
    pub name: OsString,
    pub file_type: FileType,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Descend,
    Examine,
    Ignore,
}


/// What to do with a listed entry: a directory is descended into, a wanted name is examined as a file, the rest (`.`, `..` included) is ignored.
pub fn plan(settings: &ScanSettings, name: &OsStr, file_type: FileType) -> Step {
    let dots = name == OsStr::new(".") || name == OsStr::new("..");
    if dots {
        Step::Ignore
    } else if file_type == FileType::Directory {
        Step::Descend
    } else if has_wanted_extension(settings, Path::new(name)) {
        Step::Examine
    } else {
        Step::Ignore
    }
}


/// Resolves an `Unknown` reported type with one `fstatat` that does not follow symlinks; any other type, or a failed stat, is kept as reported.
pub fn resolve_type(parent: &OwnedFd, name: &OsStr, reported: FileType) -> FileType {
    match reported {
        FileType::Unknown => statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_or(reported, |stat| FileType::from_raw_mode(stat.st_mode)),
        _ => reported,
    }
}


/// Wraps an open directory handle: `Dir` reads a second descriptor opened from it, the handle itself stays the parent of every `openat`.
pub fn level_of(handle: OwnedFd, path: PathBuf) -> io::Result<Level> {
    Dir::read_from(&handle).map(|dir| Level { handle, dir, path }).map_err(io::Error::from)
}


/// Opens a root without following a symlink as its last component.
pub fn open_root(path: &Path) -> io::Result<Level> {
    openat(rustix::fs::CWD, path, DIRECTORY_FLAGS, Mode::empty())
        .map_err(io::Error::from)
        .and_then(|handle| level_of(handle, path.to_path_buf()))
}


/// Opens `name` below `dir` once without following a symlink, then judges and reads that handle only.
pub fn load_at(parent: &OwnedFd, name: &OsStr, max_bytes: u64) -> io::Result<Loaded> {
    match openat(parent, name, FILE_FLAGS, Mode::empty()) {
        Ok(handle) => load_handle(File::from(handle), max_bytes),
        Err(Errno::LOOP) => Ok(Loaded::NotRegular),
        Err(errno) => Err(io::Error::from(errno)),
    }
}


/// A sub-directory that is now a symlink or no longer a directory was swapped after it was listed.
pub fn is_swap(errno: Errno) -> bool {
    errno == Errno::LOOP || errno == Errno::NOTDIR
}


fn open_child(level: &Level, name: &OsStr, path: PathBuf, state: &mut ScanState) -> Option<Level> {
    match openat(&level.handle, name, DIRECTORY_FLAGS, Mode::empty()) {
        Err(errno) if is_swap(errno) => {
            state.skipped.swapped += 1;
            None
        }
        Err(errno) => count_unreadable(state, io::Error::from(errno), &path),
        Ok(handle) => adopt(level_of(handle, path.clone()), state, &path),
    }
}


/// A directory whose descriptor could not be turned into a reader is counted and abandoned.
pub fn adopt(opened: io::Result<Level>, state: &mut ScanState, path: &Path) -> Option<Level> {
    match opened {
        Ok(level) => Some(level),
        Err(error) => count_unreadable(state, error, path),
    }
}


fn count_unreadable(state: &mut ScanState, error: io::Error, path: &Path) -> Option<Level> {
    state.skipped.unreadable += 1;
    record_error(state, format!("{}: {}", error.kind(), cut_path(path)));
    None
}


/// Scans one root: depth first with an explicit stack of open directories, at most `max_depth` deep and `max_listed` entries listed.
pub fn scan_root(settings: &ScanSettings, root: &Path, before_open: fn(&Path), max_listed: usize, state: &mut ScanState) {
    match open_root(root) {
        Err(error) => record_error(state, format!("{}: {}", error.kind(), cut_path(root))),
        Ok(level) => {
            let mut stack = vec![level];
            let finished = (0..max_listed)
                .try_for_each(|_| step(settings, &mut stack, before_open, state))
                .is_break();
            if !finished {
                record_error(state, format!("listing cut at {max_listed} entries: {}", cut_path(root)));
            }
        }
    }
}


fn listed_of(entry: rustix::fs::DirEntry) -> Listed {
    Listed {
        name: OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string(),
        file_type: entry.file_type(),
    }
}


/// Reads the next entry of the innermost directory; an empty stack ends the walk.
pub fn step(settings: &ScanSettings, stack: &mut Vec<Level>, before_open: fn(&Path), state: &mut ScanState) -> ControlFlow<()> {
    let flow = match stack.last_mut() {
        None => ControlFlow::Break(()),
        Some(level) => {
            let next = level.dir.next().map(|result| result.map(listed_of));
            handle_next(settings, stack, before_open, state, next)
        }
    };
    state.max_open_dirs = state.max_open_dirs.max(stack.len());
    flow
}


/// `None` is the end of the innermost directory, an error abandons it with one counted error.
pub fn handle_next(
    settings: &ScanSettings,
    stack: &mut Vec<Level>,
    before_open: fn(&Path),
    state: &mut ScanState,
    next: Option<Result<Listed, Errno>>,
) -> ControlFlow<()> {
    match next {
        None => {
            stack.pop();
        }
        Some(Err(errno)) => stack.pop().into_iter().for_each(|level| {
            state.skipped.unreadable += 1;
            record_error(state, format!("{}: {}", io::Error::from(errno).kind(), cut_path(&level.path)));
        }),
        Some(Ok(listed)) => {
            let can_descend = stack.len() < settings.max_depth;
            let opened = stack
                .last()
                .and_then(|level| visit(settings, level, can_descend, before_open, state, &listed));
            stack.extend(opened);
        }
    }
    ControlFlow::Continue(())
}


fn visit(settings: &ScanSettings, level: &Level, can_descend: bool, before_open: fn(&Path), state: &mut ScanState, listed: &Listed) -> Option<Level> {
    let path = level.path.join(&listed.name);
    let file_type = resolve_type(&level.handle, &listed.name, listed.file_type);
    before_open(&path);
    match plan(settings, &listed.name, file_type) {
        Step::Descend if can_descend => open_child(level, &listed.name, path, state),
        Step::Examine => {
            examine(settings, state, &path, || load_at(&level.handle, &listed.name, settings.max_file_bytes));
            None
        }
        Step::Descend | Step::Ignore => None,
    }
}
