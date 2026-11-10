use crate::error::SourceError;
use crate::model::Cursor;
use agent_channel::spool::{suffixed, TEMPORARY_SUFFIX};
use core_audit::log::owner_only;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;


/// A missing file is the initial state; anything else that is not `<dev> <ino> <offset>` is refused.
pub fn read_cursor(path: &Path) -> Result<Cursor, SourceError> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut fields = text.split_whitespace().map(str::parse::<u64>);
            match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some(Ok(dev)), Some(Ok(ino)), Some(Ok(offset)), None) => Ok(Cursor { dev, ino, offset }),
                _ => Err(SourceError::Cursor(path.to_path_buf())),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Cursor::default()),
        Err(error) => Err(SourceError::Io(error)),
    }
}


/// Written to a temporary file, synced, then renamed over the old one.
pub fn write_cursor(path: &Path, cursor: Cursor) -> Result<(), SourceError> {
    let temporary = suffixed(path, TEMPORARY_SUFFIX);
    let mut out = owner_only(OpenOptions::new().write(true).create(true).truncate(true)).open(&temporary)?;
    writeln!(out, "{} {} {}", cursor.dev, cursor.ino, cursor.offset)?;
    out.sync_all()?;
    Ok(fs::rename(&temporary, path)?)
}
