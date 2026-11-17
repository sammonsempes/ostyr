use crate::error::WafError;
#[cfg(unix)]
use crate::limits::{CA_FILE_MODE, GROUP_OTHER_WRITE};
use crate::limits::{TEMP_PREFIX, TEMP_SUFFIX};
use crate::model::CaRoot;
#[cfg(unix)]
use rustix::fs::{fchmod, fstat, fsync, openat, renameat, unlinkat, AtFlags, Mode, OFlags, RawMode, CWD};
#[cfg(unix)]
use rustix::process::{geteuid, getpid};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use tracing::error;


pub const UNTRUSTED_DIRECTORY: &str = "the output directory must be absolute, owned by the running user or root, and closed to group and others";


/// Absolute, `/`-separated, no empty, `.` or `..` component and no trailing `/`: every component is walked and judged.
#[cfg(unix)]
pub fn directory_text_ok(text: &str) -> bool {
    text.strip_prefix('/').is_some_and(|rest| {
        rest.split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
    })
}


/// Every path is accepted here; only a plain write and rename follow.
#[cfg(not(unix))]
pub fn directory_text_ok(_text: &str) -> bool {
    true
}


/// The path Caddy will read the CA root from, `<out_dir>/<name>`, as UTF-8 text for the JSON; the text must pass the directory grammar.
pub fn ca_root_path(out_dir: &Path, root: &CaRoot) -> Result<String, WafError> {
    let text = out_dir
        .to_str()
        .filter(|value| directory_text_ok(value))
        .ok_or(WafError::BadCaDir(UNTRUSTED_DIRECTORY))?;
    let path: PathBuf = Path::new(text).join(&root.name);
    path.to_str().map(str::to_string).ok_or(WafError::BadCaDir(UNTRUSTED_DIRECTORY))
}


/// Owned by the running user or root, and not writable by group or others.
#[cfg(unix)]
pub fn directory_trusted(mode: RawMode, owner: u32, process_user: u32) -> bool {
    (owner == process_user || owner == 0) && mode & GROUP_OTHER_WRITE == 0
}


/// A failed system call as the error that names the CA root file.
#[cfg(unix)]
pub fn io_failure(errno: rustix::io::Errno) -> WafError {
    WafError::CaWrite(errno.into())
}


/// Opens `name` below `parent` without following a symlink and judges that handle, never the path.
#[cfg(unix)]
pub fn open_judged<Parent: AsFd>(parent: Parent, name: &str) -> Result<OwnedFd, WafError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let handle = openat(parent, name, flags, Mode::empty()).map_err(io_failure)?;
    let stat = fstat(&handle).map_err(io_failure)?;
    if directory_trusted(stat.st_mode, stat.st_uid, geteuid().as_raw()) {
        Ok(handle)
    } else {
        Err(WafError::BadCaDir(UNTRUSTED_DIRECTORY))
    }
}


/// Walks the directory from `/` one component at a time, judging every handle, the root included: no symlink, no foreign or open ancestor.
#[cfg(unix)]
pub fn open_ca_directory(directory: &Path) -> Result<OwnedFd, WafError> {
    let text = directory
        .to_str()
        .filter(|value| directory_text_ok(value))
        .ok_or(WafError::BadCaDir(UNTRUSTED_DIRECTORY))?;
    let root = open_judged(CWD, "/")?;
    text.split('/')
        .skip(1)
        .try_fold(root, |parent, component| open_judged(&parent, component))
}


/// Removes the temporary file through the directory handle; a failure is logged, never silent.
#[cfg(unix)]
pub fn remove_temporary(handle: &OwnedFd, temporary: &str) {
    unlinkat(handle, temporary, AtFlags::empty()).unwrap_or_else(|errno| error!(%errno, "cannot remove the temporary CA root file"));
}


/// Writes `bytes` under `temporary` (no symlink followed), renames it over `name` and syncs the directory; the temporary goes on failure.
#[cfg(unix)]
pub fn store_in(handle: &OwnedFd, temporary: &str, name: &str, bytes: &[u8]) -> Result<(), WafError> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mode = Mode::from_raw_mode(CA_FILE_MODE);
    let created = openat(handle, temporary, flags, mode).map_err(io_failure)?;
    let mut file = File::from(created);
    file.write_all(bytes)
        .and_then(|()| fchmod(&file, mode).map_err(io::Error::from))
        .and_then(|()| file.sync_all())
        .and_then(|()| renameat(handle, temporary, handle, name).map_err(io::Error::from))
        .and_then(|()| fsync(handle).map_err(io::Error::from))
        .inspect_err(|_| remove_temporary(handle, temporary))
        .map_err(WafError::CaWrite)
}


/// Writes the checked bytes of `root` to `<out_dir>/<name>` through one directory handle, atomically, mode 0644.
#[cfg(unix)]
pub fn write_ca_root(out_dir: &Path, root: &CaRoot) -> Result<(), WafError> {
    let handle = open_ca_directory(out_dir)?;
    let temporary = format!("{TEMP_PREFIX}{}{TEMP_SUFFIX}", getpid().as_raw_nonzero());
    store_in(&handle, &temporary, &root.name, root.pem.as_bytes())
}


/// Writes the checked bytes of `root` to `<out_dir>/<name>` with a temporary file and a rename.
#[cfg(not(unix))]
pub fn write_ca_root(out_dir: &Path, root: &CaRoot) -> Result<(), WafError> {
    let temporary = out_dir.join(format!("{TEMP_PREFIX}{}{TEMP_SUFFIX}", std::process::id()));
    let target = out_dir.join(&root.name);
    std::fs::write(&temporary, root.pem.as_bytes())
        .and_then(|()| std::fs::rename(&temporary, &target))
        .map_err(WafError::CaWrite)
}
