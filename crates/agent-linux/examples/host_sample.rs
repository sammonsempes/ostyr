//! Usage: `host_sample [mount ...]`. Prints two samples of the host counters 5 seconds apart and the CPU busy ratio. Unix only.
#[cfg(unix)]
use agent_linux::capabilities::{read_bounded, SYSTEM_ROOT};
#[cfg(unix)]
use agent_linux::hostmetrics::{cpu_busy_ratio, read_sample, stat_mounts, statvfs_path};
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::thread::sleep;
#[cfg(unix)]
use std::time::Duration;


#[cfg(unix)]
const PAUSE_SECONDS: u64 = 5;


#[cfg(unix)]
fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut paths: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    paths.push(PathBuf::from(SYSTEM_ROOT));
    let first = read_sample(Path::new(SYSTEM_ROOT), read_bounded, &stat_mounts(&paths, statvfs_path));
    sleep(Duration::from_secs(PAUSE_SECONDS));
    let second = read_sample(Path::new(SYSTEM_ROOT), read_bounded, &stat_mounts(&paths, statvfs_path));
    writeln!(stdout(), "first={first:?}")?;
    writeln!(stdout(), "second={second:?}")?;
    let ratio = first
        .cpu
        .zip(second.cpu)
        .and_then(|(previous, current)| cpu_busy_ratio(&previous, &current));
    writeln!(stdout(), "busy_ratio={ratio:?}")?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
