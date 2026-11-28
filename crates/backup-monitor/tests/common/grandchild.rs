use rustix::io::Errno;
use rustix::process::{kill_process, Pid, Signal};
use std::path::{Path, PathBuf};
use std::time::Duration;


const GONE_ATTEMPTS: usize = 6000;


const GONE_POLL: Duration = Duration::from_millis(50);


pub struct Grandchild {
    pub pid_file: PathBuf,
}


pub fn read_pid(pid_file: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(pid_file)?.trim().parse()?)
}


pub fn is_gone(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| stat.rsplit_once(") ").is_some_and(|(_, rest)| rest.starts_with('Z')))
}


pub fn gone_within_guard(grandchild: &Grandchild) -> Result<bool, Box<dyn std::error::Error>> {
    let pid = read_pid(&grandchild.pid_file)?;
    Ok((0..GONE_ATTEMPTS).any(|_| {
        std::thread::sleep(GONE_POLL);
        is_gone(pid)
    }))
}


pub fn kill_pid(raw: u32) {
    match i32::try_from(raw).ok().and_then(Pid::from_raw).map(|pid| kill_process(pid, Signal::KILL)) {
        Some(Ok(())) | Some(Err(Errno::SRCH)) => {}
        Some(Err(error)) => tracing::warn!("cannot kill the test grandchild: {error}"),
        None => tracing::warn!("the test grandchild pid is out of range"),
    }
}


impl Drop for Grandchild {
    fn drop(&mut self) {
        match read_pid(&self.pid_file) {
            Ok(raw) => kill_pid(raw),
            Err(error) => tracing::warn!("no test grandchild pid to kill: {error}"),
        }
    }
}
