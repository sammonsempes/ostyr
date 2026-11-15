//! Runs `yr` as a child: cleared environment, null stdin, own process group, one bounded pipe for stdout and stderr together, a deadline that kills the group.


use crate::error::NdrError;
use crate::model::Yr;
use crate::types::ReadFn;
use rustix::process::{kill_process, kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions};
use std::ffi::OsString;
use std::io::{self, PipeWriter, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;
use tracing::{debug, warn};


const NEW_PROCESS_GROUP: i32 = 0;


const WRITABLE_BY_OTHERS: u32 = 0o022;


/// What one run left: at most `max_bytes` of the merged output and how the run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub bytes: Vec<u8>,
    pub cut: bool,
    pub timed_out: bool,
    pub exited_ok: bool,
}


/// The program must be an absolute path to a regular file that group and others cannot write.
pub fn check_program(yr: &Yr) -> Result<(), NdrError> {
    let refuse = |reason| NdrError::Program {
        path: yr.program.clone(),
        reason,
    };
    let metadata = std::fs::metadata(&yr.program).map_err(NdrError::Spawn)?;
    match (
        yr.program.is_absolute(),
        metadata.is_file(),
        metadata.permissions().mode() & WRITABLE_BY_OTHERS == 0,
    ) {
        (false, _, _) => Err(refuse("the path is not absolute")),
        (_, false, _) => Err(refuse("it is not a regular file")),
        (_, _, false) => Err(refuse("it is writable by group or others")),
        _ => Ok(()),
    }
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
