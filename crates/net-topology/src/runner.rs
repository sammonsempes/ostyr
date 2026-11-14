//! Runs `lldpcli` for one port with a deadline and a capped stdout, no helper thread (Unix only: process groups).

use crate::model::RunFailure;
use crate::ports::valid_port;
use crate::types::ClockFn;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::{kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions};
use std::io::{self, PipeReader, PipeWriter, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tracing::debug;


pub const READ_CHUNK_BYTES: usize = 65_536;


pub const WAIT_POLL_MILLIS: u64 = 10;


pub const REAP_GRACE_MILLIS: u64 = 2_000;


pub const MAX_DEADLINE_SECONDS: u64 = 3_600;


pub const NEW_PROCESS_GROUP: i32 = 0;


pub const LLDPCLI_PREFIX: [&str; 5] = ["-f", "json0", "show", "neighbors", "ports"];


pub const LLDPCLI_SUFFIX: &str = "details";


enum Output {
    Complete(Vec<u8>),
    Over,
    TimedOut,
}


fn spawn_failure(error: io::Error) -> RunFailure {
    let kind = error.kind();
    debug!(?kind, "lldpcli could not be started");
    RunFailure::Spawn
}


fn spawn(program: &Path, arguments: &[&str], stdout: PipeWriter) -> io::Result<Child> {
    Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::null())
        .process_group(NEW_PROCESS_GROUP)
        .spawn()
}


fn read_ready(reader: &mut PipeReader, buffer: &mut Vec<u8>, limit: usize, until: Instant) -> Result<Option<Output>, RunFailure> {
    let remaining = until.saturating_duration_since(Instant::now());
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(remaining.subsec_nanos()),
    };
    let mut fds = [PollFd::new(&*reader, PollFlags::IN)];
    let ready = poll(&mut fds, Some(&timeout)).map_err(io::Error::from)?;
    let mut chunk = [u8::MIN; READ_CHUNK_BYTES];
    let count = if ready == 0 { 0 } else { reader.read(&mut chunk)? };
    let room = limit.saturating_sub(buffer.len());
    buffer.extend(chunk.iter().take(count.min(room)));
    Ok(match (ready, buffer.len() >= limit, count) {
        (0, _, _) => Some(Output::TimedOut),
        (_, true, _) => Some(Output::Over),
        (_, false, 0) => Some(Output::Complete(std::mem::take(buffer))),
        (_, false, _) => None,
    })
}


fn read_step(reader: &mut PipeReader, buffer: &mut Vec<u8>, limit: usize, until: Instant) -> Result<Option<Output>, RunFailure> {
    if Instant::now() >= until {
        Ok(Some(Output::TimedOut))
    } else {
        read_ready(reader, buffer, limit, until)
    }
}


/// Reads stdout until EOF, more than `cap` bytes, or `until`; at most `cap + 1` bytes are ever kept.
pub fn read_output(reader: &mut PipeReader, cap: u64, until: Instant) -> Result<Vec<u8>, RunFailure> {
    let limit = usize::try_from(cap).unwrap_or(usize::MAX).saturating_add(1);
    let mut buffer = Vec::new();
    (0..=limit)
        .find_map(|_| read_step(reader, &mut buffer, limit, until).transpose())
        .unwrap_or(Ok(Output::Over))
        .and_then(complete_or_fail)
}


fn complete_or_fail(output: Output) -> Result<Vec<u8>, RunFailure> {
    match output {
        Output::Complete(bytes) => Ok(bytes),
        Output::Over => Err(RunFailure::TooLarge),
        Output::TimedOut => Err(RunFailure::TimedOut),
    }
}


/// Backstop count of wait rounds that covers `remaining` (capped at the maximum deadline); the clock is the primary stop (each round sleeps `WAIT_POLL_MILLIS`).
pub fn wait_polls(remaining: Duration) -> usize {
    let capped = remaining.min(Duration::from_secs(MAX_DEADLINE_SECONDS));
    usize::try_from(capped.as_millis() / u128::from(WAIT_POLL_MILLIS))
        .unwrap_or(usize::MAX)
        .saturating_add(1)
}


fn exited(child: &Child) -> Result<bool, RunFailure> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
    waitid(WaitId::Pid(Pid::from_child(child)), options)
        .map(|status| status.is_some())
        .map_err(|errno| {
            let code = errno.raw_os_error();
            debug!(code, "the child cannot be waited on");
            RunFailure::Unwaitable
        })
}


fn reap_after_exit(child: &mut Child) -> Result<Option<ExitStatus>, RunFailure> {
    let group = kill_process_group(Pid::from_child(child), Signal::KILL);
    let failed = group.is_err();
    debug!(failed, "process group cleared after exit");
    Ok(Some(child.wait()?))
}


fn wait_round(child: &mut Child, until: Instant, clock: ClockFn) -> Option<Result<Option<ExitStatus>, RunFailure>> {
    match exited(child) {
        Ok(false) if clock() >= until => Some(Ok(None)),
        Ok(false) => {
            thread::sleep(Duration::from_millis(WAIT_POLL_MILLIS));
            None
        }
        other => Some(other.and_then(|_| reap_after_exit(child))),
    }
}


/// Waits for the exit until `until` on `clock`, or the derived round count; `None` is a timeout.
pub fn wait_exit(child: &mut Child, until: Instant, clock: ClockFn) -> Result<Option<ExitStatus>, RunFailure> {
    let rounds = wait_polls(until.saturating_duration_since(clock()));
    (0..rounds).find_map(|_| wait_round(child, until, clock)).unwrap_or(Ok(None))
}


fn kill_all(child: &mut Child) {
    let group = kill_process_group(Pid::from_child(child), Signal::KILL);
    let single = child.kill();
    let failures = usize::from(group.is_err()) + usize::from(single.is_err());
    debug!(failures, "lldpcli killed");
}


fn finish(child: &mut Child, bytes: Vec<u8>, until: Instant) -> Result<Vec<u8>, RunFailure> {
    match wait_exit(child, until, &mut Instant::now)? {
        Some(status) if status.success() => Ok(bytes),
        Some(status) => Err(RunFailure::Failed {
            code: status.code(),
            read: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        }),
        None => Err(RunFailure::TimedOut),
    }
}


/// Kills the group and the pid, then reaps within `REAP_GRACE_MILLIS` on `clock`.
pub fn reap_killed(child: &mut Child, clock: ClockFn) {
    kill_all(child);
    let until = clock() + Duration::from_millis(REAP_GRACE_MILLIS);
    let reaped = matches!(wait_exit(child, until, clock), Ok(Some(_)));
    debug!(reaped, "lldpcli reaped after a kill");
}


/// Runs `program` with `arguments` (cleared environment, own process group, stdout capped at `cap` bytes, stderr discarded) within `deadline`.
pub fn run_command(program: &Path, arguments: &[&str], cap: u64, deadline: Duration) -> Result<Vec<u8>, RunFailure> {
    let until = Instant::now() + deadline.min(Duration::from_secs(MAX_DEADLINE_SECONDS));
    let (mut reader, writer) = io::pipe()?;
    let mut child = spawn(program, arguments, writer).map_err(spawn_failure)?;
    let verdict = read_output(&mut reader, cap, until).and_then(|bytes| finish(&mut child, bytes, until));
    if !matches!(verdict, Ok(_) | Err(RunFailure::Failed { .. } | RunFailure::Unwaitable)) {
        reap_killed(&mut child, &mut Instant::now);
    }
    verdict
}


/// Runs `lldpcli -f json0 show neighbors ports <port> details`; a name outside the port grammar is `Refused` before anything is spawned.
pub fn run_lldpcli(program: &Path, port: &str, cap: u64, deadline: Duration) -> Result<Vec<u8>, RunFailure> {
    if valid_port(port) {
        let arguments = LLDPCLI_PREFIX.iter().copied().chain([port, LLDPCLI_SUFFIX]).collect::<Vec<_>>();
        run_command(program, &arguments, cap, deadline)
    } else {
        Err(RunFailure::Refused)
    }
}
