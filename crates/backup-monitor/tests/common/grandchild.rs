use rustix::io::Errno;
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;


const GONE_ATTEMPTS: usize = 6000;


const ADOPT_ATTEMPTS: usize = 600;


const GONE_POLL: Duration = Duration::from_millis(50);


const FIXTURE_CMDLINE: &[u8] = b"sleep\x003600\x00";


#[derive(Debug)]
pub enum Adopted {
    Ours { pidfd: OwnedFd, pid: u32 },
    Gone,
    Foreign,
}


#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Signalled,
    Gone,
    Foreign,
}


#[derive(Debug)]
pub struct Grandchild {
    pub pid_file: PathBuf,
    pub adopted: Option<Adopted>,
}


pub fn grandchild_for(pid_file: PathBuf) -> Grandchild {
    Grandchild { pid_file, adopted: None }
}


pub fn read_pid(pid_file: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(pid_file)?.trim().parse()?)
}


pub fn is_gone(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| stat.rsplit_once(") ").is_some_and(|(_, rest)| rest.starts_with('Z')))
}


pub fn open_adopted(pid_file: &Path, attempts: usize) -> Result<Adopted, Box<dyn std::error::Error>> {
    let raw = read_pid(pid_file)?;
    let pid = Pid::from_raw(i32::try_from(raw)?).ok_or("the test grandchild pid is out of range")?;
    Ok(match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(pidfd) => match (0..attempts).find_map(|_| fixture_verdict(raw)) {
            Some(true) => Adopted::Ours { pidfd, pid: raw },
            Some(false) => Adopted::Gone,
            None => Adopted::Foreign,
        },
        Err(Errno::SRCH) => Adopted::Gone,
        Err(error) => Err(error)?,
    })
}


pub fn fixture_verdict(raw: u32) -> Option<bool> {
    let is_fixture = std::fs::read(format!("/proc/{raw}/cmdline")).is_ok_and(|cmdline| cmdline == FIXTURE_CMDLINE);
    let gone = !is_fixture && is_gone(raw);
    if !is_fixture && !gone {
        std::thread::sleep(GONE_POLL);
    }
    (is_fixture || gone).then_some(is_fixture)
}


pub fn adopt_with(grandchild: &mut Grandchild, attempts: usize) -> Result<(), Box<dyn std::error::Error>> {
    if grandchild.adopted.is_none() {
        grandchild.adopted = Some(open_adopted(&grandchild.pid_file, attempts)?);
    }
    Ok(())
}


pub fn adopt(grandchild: &mut Grandchild) -> Result<(), Box<dyn std::error::Error>> {
    adopt_with(grandchild, ADOPT_ATTEMPTS)
}


pub fn gone_within_guard(grandchild: &mut Grandchild) -> Result<bool, Box<dyn std::error::Error>> {
    adopt(grandchild)?;
    Ok(match &grandchild.adopted {
        Some(Adopted::Ours { pid, .. }) => (0..GONE_ATTEMPTS).any(|_| {
            std::thread::sleep(GONE_POLL);
            is_gone(*pid)
        }),
        Some(Adopted::Foreign) => Err("the pid file names a process that is not the fixture grandchild")?,
        _ => true,
    })
}


pub fn release(grandchild: &mut Grandchild) -> Result<Outcome, Box<dyn std::error::Error>> {
    adopt(grandchild)?;
    Ok(match &grandchild.adopted {
        Some(Adopted::Ours { pidfd, .. }) => match pidfd_send_signal(pidfd, Signal::KILL) {
            Ok(()) => Outcome::Signalled,
            Err(Errno::SRCH) => Outcome::Gone,
            Err(error) => Err(error)?,
        },
        Some(Adopted::Foreign) => Outcome::Foreign,
        _ => Outcome::Gone,
    })
}


impl Drop for Grandchild {
    fn drop(&mut self) {
        if let Err(error) = release(self) {
            tracing::warn!("cannot kill the test grandchild: {error}");
        }
    }
}
