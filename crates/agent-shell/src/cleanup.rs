use crate::account::ShellAccount;
use crate::types::CleanupFn;
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;


pub const PROC_ROOT: &str = "/proc";


/// Entries of the process table looked at in one scan.
pub const MAX_SCANNED_PROCESSES: usize = 65_536;


pub const SHELL_KILL_GRACE_SECONDS: u64 = 5;


/// Sweeps of the process table, each a SIGHUP, a grace period and a SIGKILL, until nothing of the account is left.
pub const MAX_SWEEP_ROUNDS: usize = 5;


pub const SWEEP_POLL_MILLIS: u64 = 100;


pub const MILLIS_PER_SECOND: u64 = 1000;


/// Polls after a SIGKILL before the next scan.
pub const KILL_SETTLE_POLLS: u64 = 20;


const STATE_PREFIX: &str = "State:";


const UID_PREFIX: &str = "Uid:";


const ZOMBIE_STATE: char = 'Z';


/// Where to scan, for whom, and how long to wait after a SIGHUP, in polls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepPlan {
    pub proc_root: PathBuf,
    pub uid: u32,
    pub grace_polls: u64,
    pub rounds: usize,
}


/// What `/proc/<pid>/status` says about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessFacts {
    pub real_uid: u32,
    pub zombie: bool,
}


pub fn invalid_status() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "process status without a uid or a state")
}


/// The real uid and the zombie state of a status file; a zombie holds nothing and cannot be killed.
pub fn parse_status(text: &str) -> io::Result<ProcessFacts> {
    let real_uid = text
        .lines()
        .find_map(|line| line.strip_prefix(UID_PREFIX))
        .and_then(|fields| fields.split_whitespace().next())
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(invalid_status)?;
    let zombie = text
        .lines()
        .find_map(|line| line.strip_prefix(STATE_PREFIX))
        .and_then(|state| state.trim_start().chars().next())
        .ok_or_else(invalid_status)?
        == ZOMBIE_STATE;
    Ok(ProcessFacts { real_uid, zombie })
}


/// A process that exited between the listing and the read is gone, not a failure.
pub fn tolerate_gone<Item: Default>(result: io::Result<Item>) -> io::Result<Item> {
    match result {
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound) || error.raw_os_error() == Some(libc::ESRCH) => Ok(Item::default()),
        other => other,
    }
}


/// The facts of a live process, or `None` when it has exited.
pub fn read_facts(proc_root: &Path, pid: Pid) -> io::Result<Option<ProcessFacts>> {
    let path = proc_root.join(pid.as_raw_nonzero().to_string()).join("status");
    let text = tolerate_gone(std::fs::read_to_string(path).map(Some))?;
    text.as_deref().map(parse_status).transpose()
}


pub fn is_account_process(facts: Option<ProcessFacts>, uid: u32) -> bool {
    facts.is_some_and(|known| known.real_uid == uid && !known.zombie)
}


/// Adds the process named by a directory entry of the table when it is a live process of the account; other names are skipped.
pub fn collect_process(proc_root: &Path, uid: u32, mut found: Vec<Pid>, name: &OsStr) -> io::Result<Vec<Pid>> {
    let pid = name.to_str().and_then(|text| text.parse::<i32>().ok()).and_then(Pid::from_raw);
    if let Some(known) = pid {
        if is_account_process(read_facts(proc_root, known)?, uid) {
            found.push(known);
        }
    }
    Ok(found)
}


pub fn scan_cut() -> io::Error {
    io::Error::other("the process table is larger than the scan limit")
}


/// Every live process whose real uid is the account's, from at most `cap` entries; a longer table is an error, never a clean scan.
pub fn account_processes_within(proc_root: &Path, uid: u32, cap: usize) -> io::Result<Vec<Pid>> {
    let (found, seen) =
        std::fs::read_dir(proc_root)?
            .take(cap.saturating_add(1))
            .try_fold((Vec::new(), usize::MIN), |(collected, counted), entry| {
                entry
                    .and_then(|item| collect_process(proc_root, uid, collected, &item.file_name()))
                    .map(|grown| (grown, counted + 1))
            })?;
    if seen > cap {
        Err(scan_cut())
    } else {
        Ok(found)
    }
}


/// Every live process whose real uid is the account's, from at most `MAX_SCANNED_PROCESSES` entries.
pub fn account_processes(proc_root: &Path, uid: u32) -> io::Result<Vec<Pid>> {
    account_processes_within(proc_root, uid, MAX_SCANNED_PROCESSES)
}


/// Signals a process through a pidfd opened first and re-checks the uid afterwards, so a recycled pid is never signalled.
pub fn signal_process(plan: &SweepPlan, pid: Pid, signal: Signal) -> io::Result<()> {
    let sent = pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from).and_then(|pidfd| {
        read_facts(&plan.proc_root, pid)
            .map(|facts| is_account_process(facts, plan.uid))
            .and_then(|ours| {
                if ours {
                    pidfd_send_signal(&pidfd, signal).map_err(io::Error::from)
                } else {
                    Ok(())
                }
            })
    });
    tolerate_gone(sent)
}


pub fn signal_all(plan: &SweepPlan, pids: &[Pid], signal: Signal) -> io::Result<()> {
    pids.iter().try_for_each(|pid| signal_process(plan, *pid, signal))
}


/// Scans up to `polls` times, `SWEEP_POLL_MILLIS` apart, and stops as soon as nothing is left.
pub fn settle(plan: &SweepPlan, polls: u64, left: Vec<Pid>) -> io::Result<Vec<Pid>> {
    (0..polls).try_fold(left, |remaining, _poll| {
        if remaining.is_empty() {
            Ok(remaining)
        } else {
            std::thread::sleep(Duration::from_millis(SWEEP_POLL_MILLIS));
            account_processes(&plan.proc_root, plan.uid)
        }
    })
}


/// One round: SIGHUP, the grace period, then SIGKILL for whatever is left, then a short settle; the result is the last scan.
pub fn sweep_round(plan: &SweepPlan, left: Vec<Pid>) -> io::Result<Vec<Pid>> {
    if left.is_empty() {
        Ok(left)
    } else {
        signal_all(plan, &left, Signal::HUP)?;
        let survivors = settle(plan, plan.grace_polls, left)?;
        signal_all(plan, &survivors, Signal::KILL)?;
        settle(plan, KILL_SETTLE_POLLS, survivors)
    }
}


/// Kills every process of the account, at most `rounds` times, and returns how many are still alive.
pub fn sweep(plan: &SweepPlan) -> io::Result<usize> {
    let first = account_processes(&plan.proc_root, plan.uid)?;
    let left = (0..plan.rounds).try_fold(first, |remaining, _round| sweep_round(plan, remaining))?;
    Ok(left.len())
}


pub fn production_plan(account: &ShellAccount) -> SweepPlan {
    SweepPlan {
        proc_root: PathBuf::from(PROC_ROOT),
        uid: account.uid,
        grace_polls: SHELL_KILL_GRACE_SECONDS * MILLIS_PER_SECOND / SWEEP_POLL_MILLIS,
        rounds: MAX_SWEEP_ROUNDS,
    }
}


/// The production `CleanupFn`: the sweep runs on the blocking pool.
pub fn cleanup_fn(account: &ShellAccount) -> Box<CleanupFn> {
    let plan = production_plan(account);
    Box::new(move || {
        let owned = plan.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || sweep(&owned))
                .await
                .map_err(io::Error::other)
                .and_then(std::convert::identity)
        })
    })
}
