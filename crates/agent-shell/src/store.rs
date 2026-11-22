use crate::error::StoreError;
use crate::model::{StoreEntry, MAX_SHELL_SESSION_IDS, MAX_STORE_BYTES, STORE_FILE_NAME};
#[cfg(unix)]
use crate::types::InspectFn;
use crate::verified::is_past;
use agent_command::action::valid_session_id;
use agent_command::store::private_options;
use atomicwrites::{AllowOverwrite, AtomicFile, Error as AtomicError};
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;


pub fn io_error(path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}


/// `<session id> <expires_at>`; any other line makes the whole store unreadable, so the session is refused.
pub fn parse_entry(path: &Path, line: &str) -> Result<StoreEntry, StoreError> {
    let corrupt = || StoreError::Corrupt { path: path.to_path_buf() };
    let (session_id, expiry) = line.split_once(' ').ok_or_else(corrupt)?;
    let expires_at = expiry.parse::<u64>().map_err(|_invalid| corrupt())?;
    if valid_session_id(session_id) {
        Ok(StoreEntry {
            session_id: session_id.to_owned(),
            expires_at,
        })
    } else {
        Err(corrupt())
    }
}


pub fn parse_entries(path: &Path, bytes: Vec<u8>) -> Result<Vec<StoreEntry>, StoreError> {
    let text = String::from_utf8(bytes).map_err(|_invalid| StoreError::Corrupt { path: path.to_path_buf() })?;
    text.lines().map(|line| parse_entry(path, line)).collect()
}


/// Reads at most `MAX_STORE_BYTES` and one more byte, so a larger file is refused without being buffered.
pub fn read_capped(file: File, path: &Path) -> Result<Vec<StoreEntry>, StoreError> {
    let mut bytes = Vec::new();
    file.take(MAX_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > MAX_STORE_BYTES) {
        Err(StoreError::TooLarge { path: path.to_path_buf() })
    } else {
        parse_entries(path, bytes)
    }
}


#[cfg(unix)]
pub fn open_nofollow(path: &Path, extra_flags: i32) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | extra_flags)
        .open(path)
}


#[cfg(not(unix))]
pub fn open_nofollow(path: &Path, _extra_flags: i32) -> io::Result<File> {
    File::open(path)
}


/// The kind, owner and mode of an opened handle: a regular file or a directory, owned by `owner`, nothing for group or other.
#[cfg(unix)]
pub fn judge_handle(file: &File, path: &Path, owner: u32, directory: bool) -> Result<(), StoreError> {
    judge_handle_with(file, path, (owner, directory), File::metadata)
}


/// `inspect` is injected so that a failing inspection can be tested; `rules` is the expected owner and whether a directory is expected.
#[cfg(unix)]
pub fn judge_handle_with(file: &File, path: &Path, rules: (u32, bool), inspect: InspectFn) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let (owner, directory) = rules;
    let metadata = inspect(file).map_err(|source| io_error(path, source))?;
    let kind_ok = if directory { metadata.is_dir() } else { metadata.is_file() };
    if !kind_ok {
        Err(wrong_kind(path, directory))
    } else if metadata.uid() != owner {
        Err(StoreError::Owner { path: path.to_path_buf() })
    } else {
        core_audit::log::private_mode(metadata.mode()).map_err(|source| StoreError::Insecure {
            path: path.to_path_buf(),
            source,
        })
    }
}


#[cfg(not(unix))]
pub fn judge_handle(file: &File, path: &Path, _owner: u32, directory: bool) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if directory || metadata.is_file() {
        Ok(())
    } else {
        Err(wrong_kind(path, directory))
    }
}


pub fn wrong_kind(path: &Path, directory: bool) -> StoreError {
    if directory {
        StoreError::NotDirectory { path: path.to_path_buf() }
    } else {
        StoreError::NotRegular { path: path.to_path_buf() }
    }
}


#[cfg(unix)]
pub fn check_directory(directory: &Path, owner: u32) -> Result<(), StoreError> {
    let handle = open_nofollow(directory, libc::O_DIRECTORY).map_err(|source| io_error(directory, source))?;
    judge_handle(&handle, directory, owner, true)
}


#[cfg(not(unix))]
pub fn check_directory(_directory: &Path, _owner: u32) -> Result<(), StoreError> {
    Ok(())
}


/// A missing file is a fresh store; a symlink, a FIFO, a file of another owner or one open to group or other is refused.
pub fn read_entries(path: &Path, owner: u32) -> Result<Vec<StoreEntry>, StoreError> {
    match open_nofollow(path, 0) {
        Ok(file) => {
            judge_handle(&file, path, owner, false)?;
            read_capped(file, path)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(io_error(path, source)),
    }
}


/// Temporary file (0600), fsync, rename, then fsync of the directory.
pub fn write_entries(path: &Path, entries: &[StoreEntry]) -> Result<(), StoreError> {
    AtomicFile::new(path, AllowOverwrite)
        .write_with_options(
            |file| {
                entries
                    .iter()
                    .try_for_each(|entry| writeln!(file, "{} {}", entry.session_id, entry.expires_at))
            },
            private_options(),
        )
        .map_err(|failure| match failure {
            AtomicError::Internal(source) | AtomicError::User(source) => io_error(path, source),
        })
}


/// Records a session id for good before its shell starts: an id already live is `Replayed`, a full window is `Full`.
pub fn record_session(directory: &Path, owner: u32, session_id: &str, expires_at: u64, now: u64) -> Result<(), StoreError> {
    check_directory(directory, owner)?;
    let path = directory.join(STORE_FILE_NAME);
    let mut live: Vec<StoreEntry> = read_entries(&path, owner)?
        .into_iter()
        .filter(|entry| !is_past(entry.expires_at, now))
        .collect();
    if live.iter().any(|entry| entry.session_id == session_id) {
        Err(StoreError::Replayed)
    } else if live.len() >= MAX_SHELL_SESSION_IDS {
        Err(StoreError::Full)
    } else {
        live.push(StoreEntry {
            session_id: session_id.to_owned(),
            expires_at,
        });
        write_entries(&path, &live)
    }
}
