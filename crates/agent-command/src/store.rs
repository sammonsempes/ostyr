use crate::error::StoreError;
use crate::types::SaveFn;
use core_config::watch::parent_of;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;


/// A missing file is a fresh agent (0); an unreadable or corrupt one is an error, never 0, so a replay cannot be re-accepted.
pub fn load_sequence(path: &Path) -> Result<u64, StoreError> {
    match fs::read_to_string(path) {
        Ok(text) => text.trim().parse::<u64>().map_err(|source| StoreError::Corrupt {
            path: path.to_path_buf(),
            source,
        }),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(0),
        Err(source) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}


#[cfg(unix)]
pub fn sync_directory(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}


#[cfg(not(unix))]
pub fn sync_directory(_dir: &Path) -> io::Result<()> {
    Ok(())
}


/// Temp file in the same directory, fsync, rename, fsync of the directory.
pub fn save_sequence(path: &Path, sequence: u64) -> io::Result<()> {
    let dir = parent_of(path);
    let mut staging = NamedTempFile::new_in(&dir)?;
    writeln!(staging, "{sequence}")?;
    staging.as_file().sync_all()?;
    staging.persist(path).map_err(|failure| failure.error)?;
    sync_directory(&dir)
}


pub fn file_saver(path: PathBuf) -> Box<SaveFn> {
    Box::new(move |sequence| save_sequence(&path, sequence))
}
