use crate::error::ScriptError;
use crate::fsdir::open_directory;
use crate::model::CgroupGuard;
use crate::types::{CheckFn, KillFn, PlaceFn};
use rustix::fs::{mkdirat, Mode, RawMode};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tracing::warn;


pub const PROCS_FILE: &str = "cgroup.procs";


pub const KILL_FILE: &str = "cgroup.kill";


pub const KILL_VALUE: &str = "1";


pub const REMOVE_ATTEMPTS: u32 = 50;


pub const REMOVE_PAUSE_MILLISECONDS: u64 = 10;


pub const CGROUP_PREFIX: &str = "cg-";


pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;


pub const CGROUP_DIRECTORY_MODE: RawMode = 0o755;


/// The three operations on a cgroup, injected so tests can stand in for a cgroup v2 mount.
#[derive(Debug, Clone, Copy)]
pub struct CgroupOps {
    pub check: CheckFn,
    pub place: PlaceFn,
    pub kill: KillFn,
}


/// Whether the directory behind the handle lives on a cgroup v2 filesystem (`fstatfs` magic).
#[cfg(target_os = "linux")]
pub fn is_cgroup2(directory: BorrowedFd<'_>) -> io::Result<bool> {
    let stat = rustix::fs::fstatfs(directory)?;
    Ok(u64::try_from(stat.f_type) == Ok(CGROUP2_SUPER_MAGIC))
}


/// Other unix targets have no cgroups: fail closed.
#[cfg(not(target_os = "linux"))]
pub fn is_cgroup2(_directory: BorrowedFd<'_>) -> io::Result<bool> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}


/// The control files exist on a real cgroup; they are never created, so a plain directory cannot pass for one.
pub fn write_control(directory: &Path, file: &str, text: &str) -> io::Result<()> {
    OpenOptions::new().write(true).open(directory.join(file))?.write_all(text.as_bytes())
}


/// Creates the leaf cgroup `<root>/cg-<name>` relative to the root's handle, after `check` accepted that handle; the guard removes it when dropped.
pub fn create_cgroup(root: &Path, name: &str, check: CheckFn) -> Result<CgroupGuard, ScriptError> {
    let context = "cannot create the script cgroup";
    let handle = open_directory(root).map_err(|source| ScriptError::Io { context, source })?;
    let on_cgroup2 = check(handle.as_fd()).map_err(|source| ScriptError::Io { context, source })?;
    crate::check::ensure(on_cgroup2, ScriptError::NotCgroupV2)?;
    let leaf = format!("{CGROUP_PREFIX}{name}");
    mkdirat(handle.as_fd(), leaf.as_str(), Mode::from_bits_truncate(CGROUP_DIRECTORY_MODE)).map_err(|errno| ScriptError::Io {
        context,
        source: errno.into(),
    })?;
    let path: PathBuf = root.join(leaf);
    Ok(CgroupGuard { path })
}


/// The production operations.
pub const SYSTEM_CGROUP: CgroupOps = CgroupOps {
    check: is_cgroup2,
    place: place_in_cgroup,
    kill: kill_cgroup,
};


pub fn place_in_cgroup(cgroup: &Path, pid: u32) -> io::Result<()> {
    write_control(cgroup, PROCS_FILE, &pid.to_string())
}


/// `cgroup.kill` sends SIGKILL to every process of the cgroup, wherever its group or session went.
pub fn kill_cgroup(cgroup: &Path) -> io::Result<()> {
    write_control(cgroup, KILL_FILE, KILL_VALUE)
}


/// A cgroup is removable only once its processes are gone, a moment after the kill: only EBUSY is retried, and the attempts are capped.
pub fn remove_cgroup(path: &Path, remove: &mut dyn FnMut(&Path) -> io::Result<()>, pause: &mut dyn FnMut()) -> io::Result<()> {
    (0..REMOVE_ATTEMPTS)
        .find_map(|_attempt| {
            let result = remove(path);
            match &result {
                Err(error) if error.kind() == io::ErrorKind::ResourceBusy => {
                    pause();
                    None
                }
                _ => Some(result),
            }
        })
        .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::ResourceBusy)))
}


pub fn pause_briefly() {
    thread::sleep(Duration::from_millis(REMOVE_PAUSE_MILLISECONDS));
}


impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if let Err(error) = remove_cgroup(&self.path, &mut |path| fs::remove_dir(path), &mut pause_briefly) {
            warn!(%error, "cannot remove the script cgroup");
        }
    }
}
