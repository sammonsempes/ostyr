use crate::error::{SourceError, StateDirReason};
use crate::model::{Cursor, StateDir};
use agent_channel::spool::TEMPORARY_SUFFIX;
use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};


const GROUP_OTHER_WRITE: u32 = 0o022;


pub const MAX_CURSOR_BYTES: usize = 128;


/// `<dev> <ino> <offset>` and an optional `skipping` flag (0 or 1, absent means 0).
pub fn parse_cursor(text: &str) -> Option<Cursor> {
    let mut fields = text.split_whitespace().map(str::parse::<u64>);
    match (fields.next(), fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some(Ok(dev)), Some(Ok(ino)), Some(Ok(offset)), None, None) => Some(Cursor {
            dev,
            ino,
            offset,
            skipping: false,
        }),
        (Some(Ok(dev)), Some(Ok(ino)), Some(Ok(offset)), Some(Ok(flag @ (0 | 1))), None) => Some(Cursor {
            dev,
            ino,
            offset,
            skipping: flag == 1,
        }),
        _ => None,
    }
}


/// The directory is opened once without following a symlink and judged on that handle; every later cursor operation is relative to it.
pub fn open_state_dir(cursor_file: &Path) -> Result<StateDir, SourceError> {
    let refuse = |reason| SourceError::StateDir(cursor_file.to_path_buf(), reason);
    let parent = cursor_file.parent().ok_or_else(|| refuse(StateDirReason::NoDirectory))?;
    let directory = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ENOENT) => refuse(StateDirReason::Missing),
            Some(libc::ENOTDIR | libc::ELOOP) => refuse(StateDirReason::NotDirectory),
            _ => SourceError::Io(error),
        })?;
    let metadata = handle.metadata()?;
    match state_dir_fault(metadata.uid(), rustix::process::geteuid().as_raw(), metadata.permissions().mode()) {
        None => Ok(StateDir { handle }),
        Some(reason) => Err(refuse(reason)),
    }
}


/// The reason a state directory is not trusted: it must belong to the process user or root and not be writable by group or others.
pub fn state_dir_fault(owner: u32, process_uid: u32, mode: u32) -> Option<StateDirReason> {
    if owner != process_uid && owner != 0 {
        Some(StateDirReason::WrongOwner)
    } else if mode & GROUP_OTHER_WRITE != 0 {
        Some(StateDirReason::Writable)
    } else {
        None
    }
}


fn leaf(path: &Path) -> Result<OsString, SourceError> {
    path.file_name()
        .map(OsString::from)
        .ok_or_else(|| SourceError::Cursor(path.to_path_buf()))
}


/// Opens a file of the state directory relative to it, without following a symlink or blocking on a FIFO; a missing file is `None`.
pub fn open_state_file(state: &StateDir, path: &Path) -> Result<Option<File>, SourceError> {
    let name = leaf(path)?;
    match openat(
        &state.handle,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(errno) if errno == rustix::io::Errno::NOENT => Ok(None),
        Err(errno) => Err(SourceError::Io(errno.into())),
    }
}


/// A missing file is the initial state; anything else that is not a cursor is refused.
pub fn read_cursor(state: &StateDir, cursor_file: &Path) -> Result<Cursor, SourceError> {
    match open_state_file(state, cursor_file)? {
        Some(file) => read_cursor_file(file, cursor_file),
        None => Ok(Cursor::default()),
    }
}


/// Reads at most `MAX_CURSOR_BYTES` from the opened handle, after checking it is a regular file; a longer file is refused.
pub fn read_state_text(file: File, path: &Path) -> Result<String, SourceError> {
    if file.metadata()?.is_file() {
        let mut text = String::new();
        let read = file.take(MAX_CURSOR_BYTES as u64 + 1).read_to_string(&mut text)?;
        (read <= MAX_CURSOR_BYTES)
            .then_some(text)
            .ok_or_else(|| SourceError::Cursor(path.to_path_buf()))
    } else {
        Err(SourceError::NotRegular(path.to_path_buf()))
    }
}


pub fn read_cursor_file(file: File, path: &Path) -> Result<Cursor, SourceError> {
    parse_cursor(&read_state_text(file, path)?).ok_or_else(|| SourceError::Cursor(path.to_path_buf()))
}


/// The run counter of the update inventory: a missing file is zero, anything but a decimal number is refused.
pub fn read_counter(state: &StateDir, path: &Path) -> Result<u64, SourceError> {
    match open_state_file(state, path)? {
        Some(file) => read_state_text(file, path)?
            .trim()
            .parse::<u64>()
            .map_err(|_| SourceError::Counter(path.to_path_buf())),
        None => Ok(0),
    }
}


/// A missing file is fine; any other failure to remove it is an error.
pub fn remove_stale(state: &StateDir, name: &Path) -> io::Result<()> {
    match unlinkat(&state.handle, name, AtFlags::empty()) {
        Err(errno) if errno != rustix::io::Errno::NOENT => Err(errno.into()),
        _ => Ok(()),
    }
}


/// Written to a fresh temporary file in the state directory (a stale one, or a symlink planted in its place, is removed first and never followed), synced, then renamed there.
pub fn write_state_text(state: &StateDir, path: &Path, text: &str) -> Result<(), SourceError> {
    let name = leaf(path)?;
    let mut temporary_name = name.clone();
    temporary_name.push(TEMPORARY_SUFFIX);
    let temporary = PathBuf::from(temporary_name);
    remove_stale(state, &temporary)?;
    let fd = openat(
        &state.handle,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(io::Error::from)?;
    let mut out = File::from(fd);
    out.write_all(text.as_bytes())?;
    out.sync_all()?;
    Ok(renameat(&state.handle, &temporary, &state.handle, &name).map_err(io::Error::from)?)
}


pub fn write_cursor(state: &StateDir, cursor_file: &Path, cursor: Cursor) -> Result<(), SourceError> {
    write_state_text(
        state,
        cursor_file,
        &format!("{} {} {} {}\n", cursor.dev, cursor.ino, cursor.offset, u8::from(cursor.skipping)),
    )
}
