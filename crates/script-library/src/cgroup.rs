use crate::model::CgroupGuard;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
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


/// `create(true)` is harmless on cgroupfs (the file exists) and lets a plain directory stand in for a cgroup in tests.
pub fn write_control(directory: &Path, file: &str, text: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(file))?
        .write_all(text.as_bytes())
}


/// Creates the leaf cgroup `<root>/cg-<name>`; the guard removes it when dropped.
pub fn create_cgroup(root: &Path, name: &str) -> io::Result<CgroupGuard> {
    let path: PathBuf = root.join(format!("{CGROUP_PREFIX}{name}"));
    fs::create_dir(&path)?;
    Ok(CgroupGuard { path })
}


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
