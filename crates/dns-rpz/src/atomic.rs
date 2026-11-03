use std::io::{self, Write};
use std::path::Path;
use tempfile::NamedTempFile;


/// Temporary file in the target directory, written, fsynced, then renamed over the target.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let directory = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut staging = NamedTempFile::new_in(directory)?;
    staging.write_all(bytes)?;
    staging.as_file().sync_all()?;
    staging.persist(path).map(|_| ()).map_err(|failure| failure.error)
}
