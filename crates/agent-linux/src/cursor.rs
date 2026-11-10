use crate::error::SourceError;
use crate::model::Cursor;
use agent_channel::spool::{suffixed, TEMPORARY_SUFFIX};
use core_audit::log::owner_only;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;


const GROUP_OTHER_WRITE: u32 = 0o022;


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


/// A missing file is the initial state; anything else that is not a cursor is refused.
pub fn read_cursor(path: &Path) -> Result<Cursor, SourceError> {
    match fs::read_to_string(path) {
        Ok(text) => parse_cursor(&text).ok_or_else(|| SourceError::Cursor(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Cursor::default()),
        Err(error) => Err(SourceError::Io(error)),
    }
}


/// Refuses a cursor file whose directory is missing or writable by group or others: the state directory must be root-only.
pub fn check_state_dir(cursor_file: &Path) -> Result<(), SourceError> {
    let directory = cursor_file.parent().ok_or_else(|| SourceError::StateDir(cursor_file.to_path_buf()))?;
    let mode = fs::metadata(directory)?.permissions().mode();
    if mode & GROUP_OTHER_WRITE == 0 {
        Ok(())
    } else {
        Err(SourceError::StateDir(cursor_file.to_path_buf()))
    }
}


/// A missing file is fine; any other failure to remove it is an error.
pub fn remove_stale(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}


/// Written to a fresh temporary file (a stale one, or a symlink planted in its place, is removed first and never followed), synced, then renamed.
pub fn write_cursor(path: &Path, cursor: Cursor) -> Result<(), SourceError> {
    let temporary = suffixed(path, TEMPORARY_SUFFIX);
    remove_stale(&temporary)?;
    let mut out = owner_only(OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW)).open(&temporary)?;
    writeln!(out, "{} {} {} {}", cursor.dev, cursor.ino, cursor.offset, u8::from(cursor.skipping))?;
    out.sync_all()?;
    Ok(fs::rename(&temporary, path)?)
}
