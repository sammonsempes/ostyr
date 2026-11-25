use crate::cleanup::{
    signal_process, sweep, tolerate_gone, SweepPlan, KILL_SETTLE_POLLS, MAX_SCANNED_PROCESSES, MAX_SWEEP_ROUNDS, MILLIS_PER_SECOND,
    SHELL_KILL_GRACE_SECONDS, SWEEP_POLL_MILLIS,
};
use crate::error::CgroupError;
use crate::types::{CgroupCheckFn, CgroupRemoveFn, PauseFn};
use agent_command::action::valid_session_id;
use rustix::fs::{fstatfs, mkdirat, openat, statat, unlinkat, AtFlags, Dir, Mode, OFlags, CWD};
use rustix::io::Errno;
use rustix::process::{Pid, Signal};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::Duration;


pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";


pub const SELF_CGROUP: &str = "/proc/self/cgroup";


pub const CGROUP2_MAGIC: i64 = 0x6367_7270;


pub const SESSION_PREFIX: &str = "shell-";


pub const PROCS_FILE: &str = "cgroup.procs";


pub const THREADS_FILE: &str = "cgroup.threads";


const TGID_PREFIX: &str = "Tgid:";


pub const KILL_FILE: &str = "cgroup.kill";


pub const EVENTS_FILE: &str = "cgroup.events";


const POPULATED_PREFIX: &str = "populated ";


const PATH_PREFIX: &str = "0::";


const CURRENT_DIRECTORY: &str = ".";


const PARENT_DIRECTORY: &str = "..";


const KILL_TEXT: &[u8] = b"1";


pub const MAX_SELF_CGROUP_BYTES: u64 = 4096;


pub const MAX_EVENTS_BYTES: u64 = 4096;


pub const MAX_PROCS_FILE_BYTES: u64 = 1_048_576;


pub const MAX_COMPONENT_BYTES: usize = 255;


/// The characters of an unparsable cgroup file text kept in the log line.
pub const MAX_LOGGED_CHARS: usize = 64;


/// Session cgroups looked at in one cleanup.
pub const MAX_SESSION_CGROUPS: usize = 16;


const COMPONENT_PUNCTUATION: &str = "._@:-";


const SESSION_MODE_BITS: u32 = 0o755;


/// The flags of a directory handle: no link is followed.
pub fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}


/// The flags added to every file open: no link is followed.
pub fn file_flags() -> OFlags {
    OFlags::NOFOLLOW | OFlags::CLOEXEC
}


/// Where the cgroup tree and the own cgroup file are, and how long to wait for a cgroup to empty, in polls.
#[derive(Debug, Clone)]
pub struct CgroupHost {
    pub root: PathBuf,
    pub self_cgroup: PathBuf,
    pub grace_polls: u64,
    pub kill_polls: u64,
    pub kill_rounds: usize,
    pub is_cgroup2: CgroupCheckFn,
    pub remove: CgroupRemoveFn,
    pub pause: PauseFn,
}


/// True when the directory is on a cgroup v2 filesystem.
pub fn is_cgroup2_filesystem(directory: &OwnedFd) -> io::Result<bool> {
    fstatfs(directory).map(|stat| stat.f_type == CGROUP2_MAGIC).map_err(io::Error::from)
}


pub fn remove_session(agent: &OwnedFd, name: &str) -> io::Result<()> {
    unlinkat(agent, name, AtFlags::REMOVEDIR).map_err(io::Error::from)
}


pub fn production_host() -> CgroupHost {
    CgroupHost {
        root: PathBuf::from(CGROUP_ROOT),
        self_cgroup: PathBuf::from(SELF_CGROUP),
        grace_polls: SHELL_KILL_GRACE_SECONDS * MILLIS_PER_SECOND / SWEEP_POLL_MILLIS,
        kill_polls: KILL_SETTLE_POLLS,
        kill_rounds: MAX_SWEEP_ROUNDS,
        is_cgroup2: is_cgroup2_filesystem,
        remove: remove_session,
        pause: std::thread::sleep,
    }
}


/// Reads at most `cap` bytes of text; one byte more is a refusal.
pub fn read_capped(source: &mut dyn Read, cap: u64) -> Result<String, CgroupError> {
    let mut limited = source.take(cap.saturating_add(1));
    let mut text = String::new();
    limited.read_to_string(&mut text)?;
    if limited.limit() == 0 {
        Err(CgroupError::TooLarge)
    } else {
        Ok(text)
    }
}


/// A path component: non-empty, not `.` or `..`, ASCII letters, digits and `._@:-`.
pub fn component_ok(component: &str) -> bool {
    (1..=MAX_COMPONENT_BYTES).contains(&component.len())
        && component != CURRENT_DIRECTORY
        && component != PARENT_DIRECTORY
        && component
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || COMPONENT_PUNCTUATION.contains(character))
}


pub fn path_ok(path: &str) -> bool {
    path == "/" || path.strip_prefix('/').is_some_and(|rest| rest.split('/').all(component_ok))
}


/// The path of the one `0::<path>` line of the own cgroup file; anything else is refused.
pub fn parse_self_cgroup(text: &str) -> Result<String, CgroupError> {
    let line = text
        .strip_suffix('\n')
        .filter(|body| !body.contains('\n'))
        .ok_or(CgroupError::SelfCgroupShape)?;
    let path = line.strip_prefix(PATH_PREFIX).ok_or(CgroupError::SelfCgroupShape)?;
    if path_ok(path) {
        Ok(path.to_owned())
    } else {
        Err(CgroupError::PathRefused)
    }
}


/// The cgroup directory name of a session.
pub fn session_component(session_id: &str) -> Result<String, CgroupError> {
    if valid_session_id(session_id) {
        Ok(format!("{SESSION_PREFIX}{session_id}"))
    } else {
        Err(CgroupError::SessionId)
    }
}


/// The agent's own cgroup directory, opened under a root that is checked to be cgroup v2, and its path below the root.
pub fn open_agent_directory(host: &CgroupHost) -> Result<(OwnedFd, String), CgroupError> {
    let text = read_capped(&mut File::open(&host.self_cgroup)?, MAX_SELF_CGROUP_BYTES)?;
    let path = parse_self_cgroup(&text)?;
    let root = openat(CWD, &host.root, directory_flags(), Mode::empty())?;
    if !(host.is_cgroup2)(&root)? {
        Err(CgroupError::NotCgroup2)
    } else {
        let relative = path.trim_start_matches('/').to_owned();
        let target = if relative.is_empty() { CURRENT_DIRECTORY } else { relative.as_str() };
        let agent = openat(&root, target, directory_flags(), Mode::empty())?;
        statat(&agent, KILL_FILE, AtFlags::SYMLINK_NOFOLLOW).map_err(CgroupError::KillMissing)?;
        Ok((agent, relative))
    }
}


pub fn mkdir_refusal(errno: Errno) -> CgroupError {
    match errno {
        Errno::EXIST => CgroupError::Exists,
        other => CgroupError::Sys(other),
    }
}


/// Creates the cgroup of a session, refusing one that exists, and returns the path of its `cgroup.procs`.
pub fn create_session(host: &CgroupHost, session_id: &str) -> Result<String, CgroupError> {
    let name = session_component(session_id)?;
    let (agent, relative) = open_agent_directory(host)?;
    mkdirat(&agent, &name, Mode::from_bits_retain(SESSION_MODE_BITS)).map_err(mkdir_refusal)?;
    Ok(host.root.join(relative).join(name).join(PROCS_FILE).to_string_lossy().into_owned())
}


pub fn open_directory_at(parent: &OwnedFd, name: &str) -> Result<OwnedFd, CgroupError> {
    Ok(openat(parent, name, directory_flags(), Mode::empty())?)
}


pub fn open_file_at(directory: &OwnedFd, name: &str, access: OFlags) -> Result<File, CgroupError> {
    Ok(File::from(openat(directory, name, access | file_flags(), Mode::empty())?))
}


/// The `shell-*` names among directory entries, at most `MAX_SESSION_CGROUPS`; a failing entry is an error.
pub fn collect_names(entries: &mut dyn Iterator<Item = Result<String, Errno>>) -> Result<Vec<String>, CgroupError> {
    let names = entries
        .collect::<Result<Vec<String>, Errno>>()?
        .into_iter()
        .filter(|name| name.starts_with(SESSION_PREFIX))
        .collect::<Vec<String>>();
    if names.len() > MAX_SESSION_CGROUPS {
        Err(CgroupError::TooManySessions)
    } else {
        Ok(names)
    }
}


/// The `shell-*` children of the agent's cgroup.
pub fn session_names(agent: &OwnedFd) -> Result<Vec<String>, CgroupError> {
    collect_names(&mut Dir::read_from(agent)?.map(|entry| entry.map(|item| item.file_name().to_string_lossy().into_owned())))
}


pub fn logged_prefix(text: &str) -> String {
    text.chars().take(MAX_LOGGED_CHARS).collect::<String>()
}


pub fn parse_pid(line: &str) -> Result<Pid, CgroupError> {
    line.parse::<i32>().ok().and_then(Pid::from_raw).ok_or_else(|| {
        let shown = logged_prefix(line);
        tracing::error!(?shown, "unparsable pid line in a cgroup file");
        CgroupError::Malformed
    })
}


/// The members of a session cgroup; more than `MAX_SCANNED_PROCESSES` is a refusal.
pub fn read_pids(directory: &OwnedFd) -> Result<Vec<Pid>, CgroupError> {
    let text = read_capped(&mut open_file_at(directory, PROCS_FILE, OFlags::RDONLY)?, MAX_PROCS_FILE_BYTES)?;
    let pids = text.lines().map(parse_pid).collect::<Result<Vec<Pid>, CgroupError>>()?;
    if pids.len() > MAX_SCANNED_PROCESSES {
        Err(CgroupError::TooManyProcesses)
    } else {
        Ok(pids)
    }
}


pub fn parse_populated(text: &str) -> Result<bool, CgroupError> {
    text.lines()
        .find_map(|line| line.strip_prefix(POPULATED_PREFIX))
        .and_then(|value| match value {
            "1" => Some(true),
            "0" => Some(false),
            _other => None,
        })
        .ok_or_else(|| {
            let shown = logged_prefix(text);
            tracing::error!(?shown, "unparsable cgroup.events text");
            CgroupError::Malformed
        })
}


pub fn is_populated(directory: &OwnedFd) -> Result<bool, CgroupError> {
    let text = read_capped(&mut open_file_at(directory, EVENTS_FILE, OFlags::RDONLY)?, MAX_EVENTS_BYTES)?;
    parse_populated(&text)
}


/// Polls `cgroup.events` up to `polls` times and returns whether the cgroup is still populated.
pub fn wait_unpopulated(host: &CgroupHost, directory: &OwnedFd, polls: u64) -> Result<bool, CgroupError> {
    (0..polls).try_fold(is_populated(directory)?, |busy, _poll| {
        if busy {
            (host.pause)(Duration::from_millis(SWEEP_POLL_MILLIS));
            is_populated(directory)
        } else {
            Ok(busy)
        }
    })
}


/// SIGHUP to every member of the account, through pidfds.
pub fn hang_up(plan: &SweepPlan, directory: &OwnedFd) -> Result<(), CgroupError> {
    Ok(read_pids(directory)?.iter().try_for_each(|pid| signal_process(plan, *pid, Signal::HUP))?)
}


/// One write of `1` to `cgroup.kill`.
pub fn write_kill(directory: &OwnedFd) -> Result<(), CgroupError> {
    Ok(open_file_at(directory, KILL_FILE, OFlags::WRONLY)?.write_all(KILL_TEXT)?)
}


/// The thread ids of a session cgroup; a leader that called `pthread_exit` is listed here only (kernel 7.0), with its live threads.
pub fn read_tids(directory: &OwnedFd) -> Result<Vec<Pid>, CgroupError> {
    let text = read_capped(&mut open_file_at(directory, THREADS_FILE, OFlags::RDONLY)?, MAX_PROCS_FILE_BYTES)?;
    let tids = text.lines().map(parse_pid).collect::<Result<Vec<Pid>, CgroupError>>()?;
    if tids.len() > MAX_SCANNED_PROCESSES {
        Err(CgroupError::TooManyProcesses)
    } else {
        Ok(tids)
    }
}


/// The thread group id of a status file.
pub fn parse_tgid(text: &str) -> Option<Pid> {
    text.lines()
        .find_map(|line| line.strip_prefix(TGID_PREFIX))
        .and_then(|value| value.trim().parse::<i32>().ok())
        .and_then(Pid::from_raw)
}


/// The thread group of a thread id, `None` when it exited or its status is unreadable (logged, the next round and the final population check decide).
pub fn tgid_of(plan: &SweepPlan, tid: Pid) -> Option<Pid> {
    let path = plan.proc_root.join(tid.as_raw_nonzero().to_string()).join("status");
    match tolerate_gone(std::fs::read_to_string(path)) {
        Ok(text) if text.is_empty() => None,
        Ok(text) => parse_tgid(&text).or_else(|| {
            let raw_tid = tid.as_raw_nonzero().get();
            tracing::error!(raw_tid, "thread status without a group id");
            None
        }),
        Err(error) => {
            tracing::error!(?error, "thread status unreadable");
            None
        }
    }
}


/// The deduplicated thread groups of every member: the listed pids, and the group of every listed thread.
pub fn member_groups(plan: &SweepPlan, directory: &OwnedFd) -> Result<Vec<Pid>, CgroupError> {
    let mut groups = read_pids(directory)?;
    groups.extend(read_tids(directory)?.into_iter().filter_map(|tid| tgid_of(plan, tid)));
    groups.sort_by_key(|pid| pid.as_raw_nonzero());
    groups.dedup();
    Ok(groups)
}


/// SIGKILL to every member group through pidfds: this ends a group whose leader is a zombie that `cgroup.kill` skips.
pub fn kill_members(plan: &SweepPlan, directory: &OwnedFd) -> Result<(), CgroupError> {
    let groups = member_groups(plan, directory)?;
    Ok(groups.iter().try_for_each(|pid| signal_process(plan, *pid, Signal::KILL))?)
}


/// One round: the kernel kill, the pidfd pass, then the wait for the cgroup to empty; true while it is still populated.
pub fn kill_round(host: &CgroupHost, plan: &SweepPlan, directory: &OwnedFd) -> Result<bool, CgroupError> {
    write_kill(directory)?;
    kill_members(plan, directory)?;
    wait_unpopulated(host, directory, host.kill_polls)
}


/// Rounds until the cgroup is empty, at most `kill_rounds`; true when it is still populated after them.
pub fn kill_session(host: &CgroupHost, plan: &SweepPlan, directory: &OwnedFd) -> Result<bool, CgroupError> {
    (0..host.kill_rounds).try_fold(true, |busy, _round| if busy { kill_round(host, plan, directory) } else { Ok(false) })
}


/// Members left in a cgroup that is still populated, never less than one.
pub fn session_left(directory: &OwnedFd, busy: bool) -> Result<usize, CgroupError> {
    if busy {
        Ok(read_pids(directory)?.len().max(read_tids(directory)?.len()).max(1))
    } else {
        Ok(0)
    }
}


/// 0 when the cgroup directory was removed, else 1 and a log line.
pub fn count_removal(result: io::Result<()>) -> usize {
    match result {
        Ok(()) => 0,
        Err(error) => {
            tracing::error!(?error, "shell cgroup not removed");
            1
        }
    }
}


/// Hangs up, waits the grace, kills the cgroup round by round, waits for it to empty and removes it; the result is what is left.
pub fn clear_session(host: &CgroupHost, plan: &SweepPlan, agent: &OwnedFd, name: &str) -> Result<usize, CgroupError> {
    let directory = open_directory_at(agent, name)?;
    hang_up(plan, &directory)?;
    wait_unpopulated(host, &directory, plan.grace_polls)?;
    let busy = kill_session(host, plan, &directory)?;
    let left = session_left(&directory, busy)?;
    Ok(left + count_removal((host.remove)(agent, name)))
}


/// Clears every `shell-*` cgroup of the agent and returns how many members could not be removed.
pub fn cgroup_cleanup(host: &CgroupHost, plan: &SweepPlan) -> Result<usize, CgroupError> {
    let (agent, _relative) = open_agent_directory(host)?;
    session_names(&agent)?
        .iter()
        .try_fold(usize::MIN, |total, name| clear_session(host, plan, &agent, name).map(|left| total + left))
}


/// The cgroups first, then the uid scan as the second check; the sum is what is left.
pub fn session_cleanup(host: &CgroupHost, plan: &SweepPlan) -> io::Result<usize> {
    let in_cgroups = cgroup_cleanup(host, plan)?;
    let by_uid = sweep(plan)?;
    Ok(in_cgroups + by_uid)
}
