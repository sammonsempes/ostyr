use crate::error::ConnectorError;
use crate::package::read_capped;
use crate::types::PauseFn;
use rustix::fs::{openat, Mode, OFlags};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use script_library::cgroup::{kill_cgroup, PROCS_FILE};
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::time::Duration;


pub const THREADS_FILE: &str = "cgroup.threads";


pub const EVENTS_FILE: &str = "cgroup.events";


pub const POPULATED_PREFIX: &str = "populated ";


pub const TGID_PREFIX: &str = "Tgid:";


pub const UID_PREFIX: &str = "Uid:";


pub const MAX_LIST_BYTES: u64 = 1_048_576;


pub const MAX_MEMBERS: usize = 65_536;


pub const KILL_ROUNDS: usize = 5;


pub const KILL_POLLS: u64 = 20;


pub const POLL_MILLISECONDS: u64 = 50;


/// How the kill rounds find and wait for the members of a run's cgroup; `pause` and `proc_root` are injected so tests run without waiting.
#[derive(Debug, Clone)]
pub struct KillHost {
    pub pause: PauseFn,
    pub proc_root: PathBuf,
    pub rounds: usize,
    pub polls: u64,
}


pub fn sleep_poll(pause: Duration) {
    std::thread::sleep(pause);
}


pub fn system_kill_host() -> KillHost {
    KillHost {
        pause: sleep_poll,
        proc_root: PathBuf::from("/proc"),
        rounds: KILL_ROUNDS,
        polls: KILL_POLLS,
    }
}


/// At most `MAX_LIST_BYTES` of a control file of the leaf, opened relative to the leaf handle.
pub fn read_list(leaf: BorrowedFd<'_>, file: &str) -> io::Result<String> {
    let descriptor = openat(leaf, file, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
    let mut handle = std::fs::File::from(descriptor);
    let bytes = read_capped(&mut handle, MAX_LIST_BYTES, file).map_err(io::Error::other)?;
    String::from_utf8(bytes).map_err(io::Error::other)
}


pub fn parse_ids(text: &str) -> io::Result<Vec<i32>> {
    let ids = text
        .lines()
        .map(|line| line.trim().parse::<i32>().map_err(io::Error::other))
        .collect::<io::Result<Vec<i32>>>()?;
    (ids.len() <= MAX_MEMBERS)
        .then_some(ids)
        .ok_or_else(|| io::Error::other("too many members in a cgroup list"))
}


/// The first number after `prefix` in a `/proc/<id>/status` text.
pub fn status_field(text: &str, prefix: &str) -> Option<u32> {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|number| number.parse().ok())
}


/// A process that exited between the listing and the read is gone, not a failure.
pub fn tolerate_gone<Item: Default>(result: io::Result<Item>) -> io::Result<Item> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) => {
            Ok(Item::default())
        }
        other => other,
    }
}


/// The thread group of a listed id when its real uid is the run user's; `None` when it is gone or belongs to another user.
pub fn group_of(host: &KillHost, id: i32, run_uid: u32) -> io::Result<Option<i32>> {
    let status = tolerate_gone(std::fs::read_to_string(host.proc_root.join(id.to_string()).join("status")))?;
    let group = status_field(&status, TGID_PREFIX).and_then(|value| i32::try_from(value).ok());
    Ok(group.filter(|_| status_field(&status, UID_PREFIX) == Some(run_uid)))
}


/// The deduplicated thread groups of `cgroup.procs` and of every `cgroup.threads` entry (a leader that called `pthread_exit` is listed there only).
pub fn member_groups(host: &KillHost, leaf: BorrowedFd<'_>, run_uid: u32) -> io::Result<Vec<i32>> {
    let mut ids = parse_ids(&read_list(leaf, PROCS_FILE)?)?;
    ids.extend(parse_ids(&read_list(leaf, THREADS_FILE)?)?);
    let mut groups = ids
        .iter()
        .map(|id| group_of(host, *id, run_uid))
        .collect::<io::Result<Vec<Option<i32>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<i32>>();
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}


/// Opens the pidfd first, then reads the owner of that group and signals through the pidfd only: a pid recycled before the open is another user's and is left alone.
pub fn kill_group(host: &KillHost, group: i32, run_uid: u32) -> io::Result<()> {
    let sent = Pid::from_raw(group)
        .ok_or_else(|| io::Error::other("a member group id is not a pid"))
        .and_then(|pid| pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from))
        .and_then(|pidfd| signal_if_owned(host, group, run_uid, &pidfd));
    tolerate_gone(sent)
}


/// SIGKILL through `pidfd` when the group's real uid is the run user's.
pub fn signal_if_owned(host: &KillHost, group: i32, run_uid: u32, pidfd: &OwnedFd) -> io::Result<()> {
    let status = std::fs::read_to_string(host.proc_root.join(group.to_string()).join("status"))?;
    let owned = status_field(&status, UID_PREFIX) == Some(run_uid);
    if owned {
        pidfd_send_signal(pidfd, Signal::KILL).map_err(io::Error::from)
    } else {
        Ok(())
    }
}


pub fn is_populated(leaf: BorrowedFd<'_>) -> io::Result<bool> {
    let text = read_list(leaf, EVENTS_FILE)?;
    text.lines()
        .find_map(|line| line.strip_prefix(POPULATED_PREFIX))
        .map(|value| value.trim() != "0")
        .ok_or_else(|| io::Error::other("cgroup.events has no populated line"))
}


/// Polls `cgroup.events` up to `polls` times and says whether the cgroup is still populated.
pub fn wait_unpopulated(host: &KillHost, leaf: BorrowedFd<'_>) -> io::Result<bool> {
    (0..host.polls).try_fold(is_populated(leaf)?, |busy, _poll| {
        if busy {
            (host.pause)(Duration::from_millis(POLL_MILLISECONDS));
            is_populated(leaf)
        } else {
            Ok(busy)
        }
    })
}


/// One round: `cgroup.kill`, then SIGKILL to every member group through pidfds (this ends a group whose leader is a zombie, which `cgroup.kill` skips), then the wait for the cgroup to empty.
pub fn kill_round(host: &KillHost, leaf: BorrowedFd<'_>, run_uid: u32) -> io::Result<bool> {
    kill_cgroup(leaf)?;
    member_groups(host, leaf, run_uid)?
        .iter()
        .try_for_each(|group| kill_group(host, *group, run_uid))?;
    wait_unpopulated(host, leaf)
}


/// Kill rounds until the cgroup is empty, at most `host.rounds`; never `killpg`, never a SIGTERM grace.
pub fn kill_leaf(host: &KillHost, leaf: BorrowedFd<'_>, run_uid: u32) -> Result<(), ConnectorError> {
    let busy = (0..host.rounds).try_fold(true, |still, _round| if still { kill_round(host, leaf, run_uid) } else { Ok(false) });
    busy.map_err(ConnectorError::Pipe)?
        .then_some(())
        .map_or(Ok(()), |()| Err(ConnectorError::KillFailed))
}
