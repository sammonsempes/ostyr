//! Runs `lldpcli` for one port with a deadline and a capped stdout, no helper thread (Unix only: process groups).

use crate::model::RunFailure;
use crate::ports::valid_port;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::{kill_process_group, Pid, Signal};
use std::io::{self, PipeReader, PipeWriter, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tracing::debug;


pub const READ_CHUNK_BYTES: usize = 65_536;


pub const WAIT_POLL_MILLIS: u64 = 10;


pub const MAX_WAIT_POLLS: usize = 6_200;


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


fn read_step(reader: &mut PipeReader, buffer: &mut Vec<u8>, limit: usize, until: Instant) -> Result<Option<Output>, RunFailure> {
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


/// Reads stdout until EOF, more than `cap` bytes, or `until`; at most `cap + 1` bytes are ever kept.
fn read_output(reader: &mut PipeReader, cap: u64, until: Instant) -> Result<Vec<u8>, RunFailure> {
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


fn wait_exit(child: &mut Child, until: Instant) -> io::Result<Option<ExitStatus>> {
    (0..MAX_WAIT_POLLS)
        .find_map(|_| match child.try_wait() {
            Ok(None) if Instant::now() < until => {
                thread::sleep(Duration::from_millis(WAIT_POLL_MILLIS));
                None
            }
            Ok(None) => Some(Ok(None)),
            other => Some(other),
        })
        .unwrap_or(Ok(None))
}


fn kill_all(child: &mut Child) {
    let group = kill_process_group(Pid::from_child(child), Signal::KILL);
    let single = child.kill();
    let failures = usize::from(group.is_err()) + usize::from(single.is_err());
    debug!(failures, "lldpcli killed");
}


fn finish(child: &mut Child, bytes: Vec<u8>, until: Instant) -> Result<Vec<u8>, RunFailure> {
    match wait_exit(child, until)? {
        Some(status) if status.success() => Ok(bytes),
        Some(status) => Err(RunFailure::Failed {
            code: status.code(),
            read: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        }),
        None => Err(RunFailure::TimedOut),
    }
}


fn reap_killed(child: &mut Child) {
    kill_all(child);
    let reaped = matches!(wait_exit(child, Instant::now() + Duration::from_millis(REAP_GRACE_MILLIS)), Ok(Some(_)));
    debug!(reaped, "lldpcli reaped after a kill");
}


/// Runs `program` with `arguments` (cleared environment, own process group, stdout capped at `cap` bytes, stderr discarded) within `deadline`.
pub fn run_command(program: &Path, arguments: &[&str], cap: u64, deadline: Duration) -> Result<Vec<u8>, RunFailure> {
    let until = Instant::now() + deadline.min(Duration::from_secs(MAX_DEADLINE_SECONDS));
    let (mut reader, writer) = io::pipe()?;
    let mut child = spawn(program, arguments, writer).map_err(spawn_failure)?;
    let verdict = read_output(&mut reader, cap, until).and_then(|bytes| finish(&mut child, bytes, until));
    if !matches!(verdict, Ok(_) | Err(RunFailure::Failed { .. })) {
        reap_killed(&mut child);
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
