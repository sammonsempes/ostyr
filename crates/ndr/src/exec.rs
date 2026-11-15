//! Runs `yr` as a child: cleared environment, null stdin, own process group, one bounded pipe for stdout and stderr together, a deadline that kills the group.


use crate::error::NdrError;
use crate::model::Yr;
use crate::reader::{step, Stored, DIR_FLAGS, FILE_FLAGS};
use crate::types::ReadFn;
use rustix::process::geteuid;
use rustix::process::{kill_process, kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, PipeWriter, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;
use tracing::{debug, warn};


const NEW_PROCESS_GROUP: i32 = 0;


const WRITABLE_BY_OTHERS: u32 = 0o022;


const ROOT_UID: u32 = 0;


const ROOT_PATH: &str = "/";


const THIS_DIRECTORY: &str = ".";


/// What one run left: at most `max_bytes` of the merged output and how the run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub bytes: Vec<u8>,
    pub cut: bool,
    pub timed_out: bool,
    pub exited_ok: bool,
}


/// Why a record is not trusted: a last component that is not a regular file, an owner other than root or `trusted_uid`, or write access for group or others.
pub fn distrust(metadata: &Metadata, last: bool, trusted_uid: u32) -> Option<&'static str> {
    let owner = metadata.uid();
    [
        (last && !metadata.is_file(), "it is not a regular file"),
        (
            owner != ROOT_UID && owner != trusted_uid,
            "it or a directory on its path is owned by another user",
        ),
        (
            metadata.mode() & WRITABLE_BY_OTHERS != 0,
            "it or a directory on its path is writable by group or others",
        ),
    ]
    .into_iter()
    .find_map(|(bad, reason)| bad.then_some(reason))
}


/// Opens one component below `parent` without following a symlink and judges the handle, so the path cannot change under the check.
pub fn descend(parent: &File, name: &OsStr, last: bool, trusted: (u32, &Path)) -> Result<File, NdrError> {
    let (trusted_uid, program) = trusted;
    let refuse = |reason| NdrError::Program {
        path: program.to_path_buf(),
        reason,
    };
    let flags = if last { FILE_FLAGS } else { DIR_FLAGS };
    match name
        .to_str()
        .map_or(Ok(Stored::Refused), |text| step(parent, text, flags))
        .map_err(NdrError::Spawn)?
    {
        Stored::Found(handle) => {
            let metadata = handle.metadata().map_err(NdrError::Spawn)?;
            distrust(&metadata, last, trusted_uid).map_or(Ok(handle), |reason| Err(refuse(reason)))
        }
        Stored::Refused => Err(refuse("a path component is a symlink, not a directory or not valid text")),
        Stored::Missing => Err(refuse("it does not exist")),
    }
}


/// The plain names of an absolute path; a relative path or a `..` component is `None`.
pub fn plain_names(path: &Path) -> Option<Vec<&OsStr>> {
    path.has_root().then_some(())?;
    path.components().try_fold(Vec::new(), |mut names, component| match component {
        Component::RootDir => Some(names),
        Component::Normal(name) => {
            names.push(name);
            Some(names)
        }
        _ => None,
    })
}


/// The program and every directory above it: no symlink, owned by root or `trusted_uid`, closed to group and others.
pub fn check_program_as(yr: &Yr, trusted_uid: u32) -> Result<(), NdrError> {
    let refuse = |reason| NdrError::Program {
        path: yr.program.clone(),
        reason,
    };
    let names = plain_names(&yr.program).ok_or_else(|| refuse("the path is not absolute or holds a .. component"))?;
    let (last, directories) = names.split_last().ok_or_else(|| refuse("it is not a regular file"))?;
    let root = File::open(ROOT_PATH).map_err(NdrError::Spawn)?;
    let parent = std::iter::once(OsStr::new(THIS_DIRECTORY))
        .chain(directories.iter().copied())
        .try_fold(root, |parent, name| descend(&parent, name, false, (trusted_uid, &yr.program)))?;
    descend(&parent, last, true, (trusted_uid, &yr.program)).map(drop)
}


/// `check_program_as` for the effective user of this process.
pub fn check_program(yr: &Yr) -> Result<(), NdrError> {
    check_program_as(yr, geteuid().as_raw())
}


/// The child dies with its whole group when the deadline passes before `done` is dropped; a missing group is expected and only logged.
pub fn kill_all(pid: Pid) -> rustix::io::Result<()> {
    let _group = kill_process_group(pid, Signal::KILL).inspect_err(|error| debug!(error = ?error, "no process group to kill"));
    kill_process(pid, Signal::KILL).inspect_err(|error| debug!(error = ?error, "no process to kill"))
}


/// Kills the child and its group; a failure is logged, the caller goes on to reap.
pub fn kill_logged(pid: Pid) {
    kill_all(pid).unwrap_or_else(|error| warn!(error = ?error, "yr could not be killed"));
}


/// The watchdog: kills the child at the deadline unless the run is over first.
pub fn watch(pid: Pid, done: &Receiver<()>, deadline: Duration, timed_out: &AtomicBool) {
    if done.recv_timeout(deadline) == Err(RecvTimeoutError::Timeout) {
        timed_out.store(true, Ordering::SeqCst);
        warn!("yr passed its deadline, killing it");
        kill_logged(pid);
    }
}


/// Reads at most `max_bytes` from the pipe; the flag is `true` when the child wrote more, which is never buffered.
pub fn read_bounded(reader: &mut dyn Read, max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    reader.take((max_bytes as u64).saturating_add(1)).read_to_end(&mut bytes)?;
    let cut = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    Ok((bytes, cut))
}


fn spawn(program: &Path, args: &[OsString], writer: PipeWriter) -> io::Result<Child> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(writer.try_clone()?)
        .stderr(writer)
        .process_group(NEW_PROCESS_GROUP);
    command.spawn()
}


/// Waits for the exit without reaping, so the watchdog can never signal a reused pid.
pub fn wait_exit(pid: Pid) {
    waitid(WaitId::Pid(pid), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT).unwrap_or_else(|errno| {
        let code = errno.raw_os_error();
        debug!(code, "the child cannot be waited on without reaping");
        None
    });
}


/// Whether the reaped child exited with success; a failed wait is logged and counts as a failure.
pub fn exit_ok(waited: io::Result<ExitStatus>) -> bool {
    waited.map_or_else(
        |error| {
            warn!(error = ?error, "yr could not be reaped");
            false
        },
        |status| status.success(),
    )
}


/// Runs `yr args...` and returns the bounded stream; the child is always reaped before this returns.
pub fn run_bounded(yr: &Yr, args: &[OsString], max_bytes: usize, deadline: Duration) -> Result<Captured, NdrError> {
    run_with(yr, args, max_bytes, deadline, read_bounded)
}


/// `run_bounded` with the pipe reader injected, so a failing read is testable.
pub fn run_with(yr: &Yr, args: &[OsString], max_bytes: usize, deadline: Duration, reader_fn: ReadFn) -> Result<Captured, NdrError> {
    check_program(yr)?;
    let (mut reader, writer) = io::pipe().map_err(NdrError::Spawn)?;
    let mut child = spawn(&yr.program, args, writer).map_err(NdrError::Spawn)?;
    let pid = Pid::from_child(&child);
    let timed_out = AtomicBool::new(false);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let flag = &timed_out;
    let read = thread::scope(|scope| {
        scope.spawn(move || watch(pid, &done_rx, deadline, flag));
        let read = reader_fn(&mut reader, max_bytes);
        if read.as_ref().map_or(true, |(_, cut)| *cut) {
            kill_logged(pid);
        }
        wait_exit(pid);
        drop(done_tx);
        read
    });
    let exited_ok = exit_ok(child.wait());
    let (bytes, cut) = read.map_err(NdrError::Output)?;
    Ok(Captured {
        bytes,
        cut,
        timed_out: timed_out.load(Ordering::SeqCst),
        exited_ok,
    })
}
