use crate::error::ScriptError;
use crate::fsdir::{io_failure, open_child_directory, open_directory};
use crate::model::{LimitHit, Limits};
use crate::types::{CheckFn, EventsFn, KillFn, LimitFn, PlaceFn};
use rustix::fs::{accessat, mkdirat, openat, unlinkat, Access, AtFlags, Mode, OFlags, RawMode};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tracing::{debug, warn};


pub const PROCS_FILE: &str = "cgroup.procs";


pub const KILL_FILE: &str = "cgroup.kill";


pub const KILL_VALUE: &str = "1";


pub const MEMORY_MAX_FILE: &str = "memory.max";


pub const PIDS_MAX_FILE: &str = "pids.max";


pub const SWAP_MAX_FILE: &str = "memory.swap.max";


pub const NO_SWAP: &str = "0";


pub const CPU_MAX_FILE: &str = "cpu.max";


pub const MEMORY_EVENTS_FILE: &str = "memory.events";


pub const PIDS_EVENTS_FILE: &str = "pids.events";


pub const OOM_KILL_KEY: &str = "oom_kill";


pub const PIDS_REFUSED_KEY: &str = "max";


pub const CPU_PERIOD_MICROSECONDS: u64 = 100_000;


pub const CPU_MICROSECONDS_PER_PERCENT: u64 = 1000;


pub const MAX_CONTROL_BYTES: u64 = 4096;


pub const REMOVE_ATTEMPTS: u32 = 50;


pub const REMOVE_PAUSE_MILLISECONDS: u64 = 10;


pub const CGROUP_PREFIX: &str = "cg-";


pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;


pub const CGROUP_DIRECTORY_MODE: RawMode = 0o755;


/// The operations on a cgroup, injected so tests can stand in for a cgroup v2 mount.
#[derive(Debug, Clone, Copy)]
pub struct CgroupOps {
    pub check: CheckFn,
    pub place: PlaceFn,
    pub kill: KillFn,
    pub limit: LimitFn,
    pub events: EventsFn,
}


/// A leaf cgroup created for one run, removed on drop; every control file is reached through `leaf`, the handle opened once below `root`.
#[derive(Debug)]
pub struct CgroupGuard {
    pub path: PathBuf,
    pub name: String,
    pub root: OwnedFd,
    pub leaf: OwnedFd,
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
pub fn write_control(directory: BorrowedFd<'_>, file: &str, text: &str) -> io::Result<()> {
    let descriptor = openat(directory, file, OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
    File::from(descriptor).write_all(text.as_bytes())
}


/// At most `MAX_CONTROL_BYTES` of a control file.
pub fn read_control(directory: BorrowedFd<'_>, file: &str) -> io::Result<String> {
    let descriptor = openat(directory, file, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
    let mut text = String::new();
    File::from(descriptor).take(MAX_CONTROL_BYTES).read_to_string(&mut text)?;
    Ok(text)
}


/// Creates the leaf cgroup `<root>/cg-<name>` relative to the root's handle, after `check` accepted that handle, and opens it once; the guard removes it when dropped.
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
    let opened = open_child_directory(handle.as_fd(), OsStr::new(&leaf)).map_err(io_failure(context))?;
    let path = root.join(&leaf);
    Ok(CgroupGuard {
        path,
        leaf: opened,
        name: leaf,
        root: handle,
    })
}


/// The production operations.
pub const SYSTEM_CGROUP: CgroupOps = CgroupOps {
    check: is_cgroup2,
    place: place_in_cgroup,
    kill: kill_cgroup,
    limit: apply_limits,
    events: read_events,
};


/// `cgroup.kill` must exist (kernel 5.14+) before the process enters: without it the cgroup could not be emptied, so the run fails closed.
pub fn place_in_cgroup(leaf: BorrowedFd<'_>, pid: u32) -> io::Result<()> {
    accessat(leaf, KILL_FILE, Access::WRITE_OK, AtFlags::empty())?;
    write_control(leaf, PROCS_FILE, &pid.to_string())
}


/// `cgroup.kill` sends SIGKILL to every process of the cgroup, wherever its group or session went.
pub fn kill_cgroup(leaf: BorrowedFd<'_>) -> io::Result<()> {
    write_control(leaf, KILL_FILE, KILL_VALUE)
}


/// Writes `memory.max`, `pids.max` and, when declared, `cpu.max`; a controller that is not enabled makes this fail, so the run does not start unlimited.
pub fn apply_limits(leaf: BorrowedFd<'_>, limits: &Limits) -> io::Result<()> {
    write_control(leaf, MEMORY_MAX_FILE, &limits.memory_bytes.to_string())?;
    write_control(leaf, SWAP_MAX_FILE, NO_SWAP).or_else(|error| match error.kind() {
        io::ErrorKind::NotFound => {
            debug!("swap accounting is off, the memory limit is the only one");
            Ok(())
        }
        _ => Err(error),
    })?;
    write_control(leaf, PIDS_MAX_FILE, &limits.pids.to_string())?;
    limits.cpu_percent.map_or(Ok(()), |percent| {
        write_control(
            leaf,
            CPU_MAX_FILE,
            &format!("{} {CPU_PERIOD_MICROSECONDS}", percent.saturating_mul(CPU_MICROSECONDS_PER_PERCENT)),
        )
    })
}


/// The value of `key` in a flat keyed file (`memory.events`); a missing key or a bad number is an error.
pub fn event_count(text: &str, key: &str) -> io::Result<u64> {
    text.lines()
        .filter_map(|line| line.split_once(' '))
        .find(|(name, _)| *name == key)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
        .1
        .trim()
        .parse()
        .map_err(io::Error::other)
}


pub fn count_in(leaf: BorrowedFd<'_>, file: &str, key: &str) -> io::Result<u64> {
    let text = read_control(leaf, file)?;
    event_count(&text, key)
}


/// A memory kill wins over a refused fork.
pub fn read_events(leaf: BorrowedFd<'_>) -> io::Result<Option<LimitHit>> {
    let oom_kills = count_in(leaf, MEMORY_EVENTS_FILE, OOM_KILL_KEY)?;
    let refused = count_in(leaf, PIDS_EVENTS_FILE, PIDS_REFUSED_KEY)?;
    Ok(match (oom_kills, refused) {
        (0, 0) => None,
        (0, _) => Some(LimitHit::Pids),
        _ => Some(LimitHit::Memory),
    })
}


/// A cgroup is removable only once its processes are gone, a moment after the kill: only EBUSY is retried, and the attempts are capped.
pub fn remove_cgroup(remove: &mut dyn FnMut() -> io::Result<()>, pause: &mut dyn FnMut()) -> io::Result<()> {
    (0..REMOVE_ATTEMPTS)
        .find_map(|_attempt| {
            let result = remove();
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
        let result = remove_cgroup(
            &mut || unlinkat(self.root.as_fd(), self.name.as_str(), AtFlags::REMOVEDIR).map_err(io::Error::from),
            &mut pause_briefly,
        );
        if let Err(error) = result {
            warn!(%error, "cannot remove the script cgroup");
        }
    }
}
