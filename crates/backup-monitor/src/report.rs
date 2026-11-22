//! The example runner's previous-run files: levels made like the Borg ones, files written and read through the checked handle (Unix only).

use crate::borg::{base_refusal, make_level, make_private_directory, private_handle, BorgError};
use core_pg::scope::{tenant_of, TenantScope};
use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use thiserror::Error;


pub const REPORT_DIRECTORY: &str = "reports";


/// A fixed category per failure: no path or file text is kept.
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("report directory refused: {0}")]
    Directory(#[from] BorgError),
    #[error("report file is not a regular file or its name is refused")]
    Refused,
    #[error("report file I/O failed: {0}")]
    Io(#[from] io::Error),
}


/// `<state>/reports/<tenant>`: `<state>` must be trusted, each level is made 0700 when absent and must be exactly 0700 (an existing looser one is refused).
pub fn report_directory(state: &Path, tenant: &TenantScope, euid: u32) -> Result<OwnedFd, ReportError> {
    report_directory_with(state, tenant, euid, make_private_directory)
}


/// `report_directory` with the directory maker injected, so a failing `mkdir` can be tested.
pub fn report_directory_with(state: &Path, tenant: &TenantScope, euid: u32, make: fn(&Path) -> io::Result<()>) -> Result<OwnedFd, ReportError> {
    open_trusted(state, euid)?;
    let (reports, _) = make_level(state, REPORT_DIRECTORY, euid, make)?;
    private_handle(&reports, euid)?;
    let (level, _) = make_level(&reports, tenant_of(tenant), euid, make)?;
    Ok(private_handle(&level, euid)?)
}


fn open_trusted(state: &Path, euid: u32) -> Result<OwnedFd, ReportError> {
    Ok(core_config::trusted_dir::open_trusted_dir(state, euid).map_err(base_refusal)?)
}


fn open_in(directory: &OwnedFd, name: &str, flags: OFlags) -> Result<File, io::Error> {
    Ok(File::from(openat(
        directory,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )?))
}


fn plain_name(name: &str) -> Result<(), ReportError> {
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        Err(ReportError::Refused)
    } else {
        Ok(())
    }
}


fn remove_stale(directory: &OwnedFd, name: &str) -> Result<(), ReportError> {
    match unlinkat(directory, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(ReportError::Io(io::Error::from(errno))),
    }
}


/// Writes the whole of `bytes`; a failing writer is an `Io` error.
pub fn write_all_to(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), ReportError> {
    Ok(writer.write_all(bytes)?)
}


/// Writes `name` through the checked directory handle: a fresh 0600 temporary (`O_CREAT|O_EXCL|O_NOFOLLOW`), then a rename over `name`, so an existing file or symlink is replaced, never followed or kept.
pub fn write_report(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), ReportError> {
    plain_name(name)?;
    let temporary = format!(".{name}.tmp");
    remove_stale(directory, &temporary)?;
    let mut file = open_in(directory, &temporary, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
    write_all_to(&mut file, bytes)?;
    Ok(renameat(directory, &temporary, directory, name).map_err(io::Error::from)?)
}


/// Reads at most `cap` bytes from a reader; a failing reader is an `Io` error.
pub fn read_up_to(reader: &mut dyn Read, cap: u64) -> Result<Vec<u8>, ReportError> {
    let mut bytes = Vec::new();
    Read::take(reader, cap).read_to_end(&mut bytes)?;
    Ok(bytes)
}


/// Reads `name` through the checked directory handle (`O_NOFOLLOW|O_NONBLOCK`, regular file of `euid`); absent is `None`, at most `cap` bytes.
pub fn read_report(directory: &OwnedFd, name: &str, euid: u32, cap: u64) -> Result<Option<Vec<u8>>, ReportError> {
    plain_name(name)?;
    match open_in(directory, name, OFlags::RDONLY) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ReportError::Io(error)),
        Ok(mut file) => {
            let metadata = file.metadata()?;
            if metadata.is_file() && metadata.uid() == euid {
                read_up_to(&mut file, cap).map(Some)
            } else {
                Err(ReportError::Refused)
            }
        }
    }
}
