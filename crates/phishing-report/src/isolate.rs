//! Runs the parse in a child process under an address-space limit (T605A cycle 3): the rules are in the crate notes.

use crate::error::TriageError;
use crate::limits::{check_child_limits, Limits};
use crate::model::{ReporterPolicy, Triage};
use crate::policy::check_policy;
use crate::triage::triage_with;
use crate::types::{GroupKillFn, Job, ReadFn, SerializeFn, SpawnFn};
use core_config::trusted_program::open_trusted_program;
use rustix::process::{geteuid, kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::{debug, warn};


pub const CHILD_ARGUMENT: &str = "--ostyr-phishing-parse-child";


pub const PRLIMIT_PROGRAM: &str = "/usr/bin/prlimit";


pub const EXIT_TOO_LARGE: u8 = 2;


pub const EXIT_UNPARSABLE: u8 = 3;


pub const EXIT_FAILED: u8 = 4;


pub const REQUEST_LINE_BYTES: usize = 512 * 1024;


pub const REAP_POLL_MILLIS: u64 = 10;


pub const REAP_GRACE_MILLIS: u64 = 2_000;


const NEW_PROCESS_GROUP: i32 = 0;


pub const PROC_STATUS: &str = "/proc/self/status";


pub const MAX_STATUS_BYTES: u64 = 1_048_576;


pub const SIGCHLD_NUMBER: u32 = 17;


pub const HEX_RADIX: u32 = 16;


const SIGIGN_PREFIX: &str = "SigIgn:";


const PROFILE_VARIABLE: &str = "LLVM_PROFILE_FILE";


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Isolation {
    pub prlimit: PathBuf,
    pub program: PathBuf,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRequest {
    pub trusted: Vec<String>,
    pub reporters: ReporterPolicy,
    pub limits: Limits,
}


/// The exit code a child reports for a failed triage.
pub fn exit_code(error: TriageError) -> u8 {
    match error {
        TriageError::TooLarge => EXIT_TOO_LARGE,
        TriageError::Unparsable => EXIT_UNPARSABLE,
        TriageError::ChildMemory
        | TriageError::ChildUnwaitable
        | TriageError::ChildDeadline
        | TriageError::ChildFailed
        | TriageError::ChildOutput
        | TriageError::ChildProgram
        | TriageError::LimitsRefused
        | TriageError::PolicyRefused => EXIT_FAILED,
    }
}


fn read_request(input: &mut dyn BufRead) -> Result<ChildRequest, u8> {
    let mut line = Vec::new();
    Read::take(&mut *input, REQUEST_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| EXIT_FAILED)?;
    let complete = line.pop() == Some(b'\n');
    complete.then_some(()).ok_or(EXIT_FAILED)?;
    serde_json::from_slice(&line).map_err(|_| EXIT_FAILED)
}


fn read_message(input: &mut dyn BufRead, limit: usize) -> Result<Vec<u8>, u8> {
    let mut raw = Vec::new();
    Read::take(&mut *input, limit as u64 + 1).read_to_end(&mut raw).map_err(|_| EXIT_FAILED)?;
    (raw.len() <= limit).then_some(raw).ok_or(EXIT_TOO_LARGE)
}


fn run_child(input: &mut dyn BufRead, output: &mut dyn Write) -> Result<(), u8> {
    let request = read_request(input)?;
    let raw = read_message(input, request.limits.message_bytes)?;
    let record = triage_with(&raw, &request.trusted, &request.reporters, &request.limits).map_err(exit_code)?;
    serde_json::to_writer(&mut *output, &record).map_err(|_| EXIT_FAILED)?;
    output.flush().map_err(|_| EXIT_FAILED)
}


/// The child entry point: a request line (JSON), then the raw message, on `input`; the record as JSON on `output`; the exit code.
pub fn parse_child_main(input: &mut dyn BufRead, output: &mut dyn Write) -> u8 {
    run_child(input, output).map_or_else(|code| code, |()| 0)
}


/// Reads at most `max_bytes`; the flag is `true` when the child wrote more, which is never buffered.
pub fn read_capped(reader: &mut dyn Read, max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    reader.take((max_bytes as u64).saturating_add(1)).read_to_end(&mut bytes)?;
    let cut = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    Ok((bytes, cut))
}


/// The production isolation: `/usr/bin/prlimit` and the running executable.
pub fn default_isolation() -> Result<Isolation, TriageError> {
    default_isolation_from(std::env::current_exe())
}


/// `default_isolation` with the executable path injected, so a failing lookup is testable.
pub fn default_isolation_from(current: io::Result<PathBuf>) -> Result<Isolation, TriageError> {
    let program = current.or(Err(TriageError::ChildProgram))?;
    Ok(Isolation {
        prlimit: PathBuf::from(PRLIMIT_PROGRAM),
        program,
    })
}


fn program_refused(error: &core_config::trusted_program::TrustedProgramError) -> TriageError {
    let reason = error.to_string();
    warn!(reason, "an isolation program is not trusted");
    TriageError::ChildProgram
}


fn check_programs(isolation: &Isolation) -> Result<(), TriageError> {
    let uid = geteuid().as_raw();
    open_trusted_program(&isolation.prlimit, uid).map_err(|error| program_refused(&error))?;
    open_trusted_program(&isolation.program, uid)
        .map(|_handle| ())
        .map_err(|error| program_refused(&error))
}


/// `prlimit --as=N --core=0 -- <program> <child argument>`: the limit binds from the first instruction, no `pre_exec`.
pub fn child_command(isolation: &Isolation, limits: &Limits) -> Command {
    let mut command = Command::new(&isolation.prlimit);
    command
        .arg(format!("--as={}", limits.child_address_space))
        .arg("--core=0")
        .arg("--")
        .arg(&isolation.program)
        .arg(CHILD_ARGUMENT);
    command
}


/// The stdin of the child: the request line, then the raw message; the serializer is injected so a failing one is testable.
pub fn payload(raw: &[u8], trusted: &[String], reporters: &ReporterPolicy, limits: &Limits, serialize: SerializeFn) -> Result<Vec<u8>, TriageError> {
    let request = ChildRequest {
        trusted: trusted.to_vec(),
        reporters: reporters.clone(),
        limits: limits.clone(),
    };
    let mut bytes = serialize(&request).or(Err(TriageError::ChildFailed))?;
    (bytes.len() <= REQUEST_LINE_BYTES).then_some(()).ok_or(TriageError::LimitsRefused)?;
    bytes.push(b'\n');
    bytes.extend_from_slice(raw);
    Ok(bytes)
}


/// One reported message in, one record out, parsed by a child under `limits.child_address_space`.
pub fn triage_isolated(
    raw: &[u8],
    trusted: &[String],
    reporters: &ReporterPolicy,
    limits: &Limits,
    isolation: &Isolation,
) -> Result<Triage, TriageError> {
    check_child_limits(limits)?;
    check_policy(reporters)?;
    (raw.len() <= limits.message_bytes).then_some(()).ok_or(TriageError::TooLarge)?;
    check_programs(isolation)?;
    let bytes = payload(raw, trusted, reporters, limits, serde_json::to_vec)?;
    run_child_process(
        child_command(isolation, limits),
        bytes,
        limits,
        REAP_GRACE_MILLIS,
        (read_capped, spawn_job, kill_group),
    )
}


/// Kills what the child left in its process group; the exited child is still a zombie, so the pgid cannot be recycled.
pub fn kill_group(pid: Pid) {
    let group = kill_process_group(pid, Signal::KILL);
    let outcome = format!("{group:?}");
    debug!(outcome, "the child group was swept");
}


/// The writer thread body: the payload into the child's stdin, the outcome logged.
pub fn write_payload(stdin: &mut dyn Write, bytes: &[u8]) {
    let written = stdin.write_all(bytes);
    let outcome = format!("{:?}", written.as_ref().err().map(io::Error::kind));
    debug!(outcome, "the child input was written");
}


/// The reader thread body: the bounded output handed to the parent.
pub fn send_output(sender: &mpsc::Sender<io::Result<(Vec<u8>, bool)>>, source: &mut dyn Read, cap: usize, reader: ReadFn) {
    let output = reader(source, cap);
    let delivered = sender.send(output).is_ok();
    debug!(delivered, "the child output was handed over");
}


/// Spawns one helper thread.
pub fn spawn_job(job: Job) -> io::Result<()> {
    thread::Builder::new().spawn(job).map(drop)
}


fn converse(streams: (ChildStdin, ChildStdout), bytes: Vec<u8>, limits: &Limits, plumbing: (ReadFn, SpawnFn)) -> Result<Vec<u8>, TriageError> {
    let (stdin, stdout) = streams;
    let (reader, spawner) = plumbing;
    let (sender, receiver) = mpsc::channel();
    let cap = limits.child_output_bytes;
    let writer_job: Job = Box::new(move || write_payload(&mut { stdin }, &bytes));
    let reader_job: Job = Box::new(move || send_output(&sender, &mut { stdout }, cap, reader));
    let started = spawner(writer_job).and(spawner(reader_job));
    started.or(Err(TriageError::ChildFailed))?;
    match receiver.recv_timeout(Duration::from_millis(limits.child_deadline_millis)) {
        Ok(Ok((output, false))) => Ok(output),
        Ok(Ok((_, true))) => Err(TriageError::ChildOutput),
        Ok(Err(_)) => Err(TriageError::ChildFailed),
        Err(_) => Err(TriageError::ChildDeadline),
    }
}


/// Whether the child has exited, read without reaping it: the zombie keeps its pid and process group; an error means the pid is not ours to signal.
pub fn exited(pid: Pid) -> io::Result<bool> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
    waitid(WaitId::Pid(pid), options).map(|status| status.is_some()).map_err(io::Error::from)
}


/// Waits for the exit in bounded polls without reaping; `false` when the child still runs after `polls`.
pub fn await_exit(pid: Pid, polls: u64) -> io::Result<bool> {
    (0..polls)
        .find_map(|_| match exited(pid) {
            Ok(false) => {
                thread::sleep(Duration::from_millis(REAP_POLL_MILLIS));
                None
            }
            other => Some(other),
        })
        .unwrap_or(Ok(false))
}


/// The deadline path: signals only a leader that `waitid` still shows (running or zombie), then reaps; an error signals nothing.
pub fn stop(pid: Pid, child: &mut Child, error: TriageError, group_kill: GroupKillFn) -> Result<Triage, TriageError> {
    let present = exited(pid).map_err(|failure| {
        let kind = format!("{:?}", failure.kind());
        warn!(kind, "the child cannot be waited on, nothing is signalled");
        TriageError::ChildUnwaitable
    })?;
    debug!(present, "the child was present before the kill");
    group_kill(pid);
    let killed = child.kill();
    let kill_outcome = format!("{:?}", killed.as_ref().err().map(io::Error::kind));
    debug!(kill_outcome, "the child was killed");
    let waited = child.wait();
    let outcome = format!("{:?}", waited.as_ref().err().map(io::Error::kind));
    debug!(outcome, "the killed child was reaped");
    Err(error)
}


/// True when the `SigIgn` mask of the status file at `status` has SIGCHLD set; a file or mask that cannot be read is `ChildUnwaitable`.
pub fn sigchld_ignored(status: &Path) -> Result<bool, TriageError> {
    let mut text = String::new();
    File::open(status)
        .and_then(|file| file.take(MAX_STATUS_BYTES).read_to_string(&mut text))
        .or(Err(TriageError::ChildUnwaitable))?;
    let mask = text
        .lines()
        .find_map(|line| line.strip_prefix(SIGIGN_PREFIX))
        .ok_or(TriageError::ChildUnwaitable)?;
    let bits = u64::from_str_radix(mask.trim(), HEX_RADIX).or(Err(TriageError::ChildUnwaitable))?;
    Ok(bits & (1 << (SIGCHLD_NUMBER - 1)) != 0)
}


/// Refuses to run when SIGCHLD is ignored: the leader would be reaped by the kernel and its pid could be reused before a signal.
pub fn require_waitable(status: &Path) -> Result<(), TriageError> {
    let ignored = sigchld_ignored(status)?;
    debug!(ignored, "the SIGCHLD disposition was read");
    (!ignored).then_some(()).ok_or(TriageError::ChildUnwaitable)
}


fn parse_record(bytes: &[u8]) -> Result<Triage, TriageError> {
    serde_json::from_slice(bytes).map_err(|error| {
        let detail = format!("{:?} line {} column {}", error.classify(), error.line(), error.column());
        warn!(detail, "the child output is not a triage record");
        TriageError::ChildOutput
    })
}


/// The verdict on an exited child: its exit code, or the abort an allocation failure under the address-space limit causes.
pub fn decide(status: ExitStatus, bytes: &[u8]) -> Result<Triage, TriageError> {
    match (status.code(), status.signal()) {
        (Some(0), _) => parse_record(bytes),
        (Some(code), _) if code == i32::from(EXIT_TOO_LARGE) => Err(TriageError::TooLarge),
        (Some(code), _) if code == i32::from(EXIT_UNPARSABLE) => Err(TriageError::Unparsable),
        (_, Some(signal)) if signal == Signal::ABORT.as_raw() => Err(TriageError::ChildMemory),
        _ => Err(TriageError::ChildFailed),
    }
}


pub fn settle(pid: Pid, child: &mut Child, bytes: &[u8], timing: (u64, GroupKillFn)) -> Result<Triage, TriageError> {
    let (grace_millis, group_kill) = timing;
    let polls = grace_millis / REAP_POLL_MILLIS + 1;
    let waited = await_exit(pid, polls);
    let outcome = format!("{:?}", waited.as_ref().err().map(io::Error::kind));
    debug!(outcome, "the child exit was awaited");
    match waited {
        Ok(true) => {
            group_kill(pid);
            let reaped = child.wait();
            let reaped_outcome = format!("{:?}", reaped.as_ref().err().map(io::Error::kind));
            debug!(reaped_outcome, "the child was reaped after the group kill");
            reaped.map_or(Err(TriageError::ChildFailed), |status| decide(status, bytes))
        }
        Ok(false) => stop(pid, child, TriageError::ChildFailed, group_kill),
        Err(_) => Err(TriageError::ChildUnwaitable),
    }
}


/// Runs a prepared child command: the payload on its stdin, a bounded stdout, a deadline; every failure is one fixed variant.
pub fn run_child_process(
    command: Command,
    bytes: Vec<u8>,
    limits: &Limits,
    grace_millis: u64,
    plumbing: (ReadFn, SpawnFn, GroupKillFn),
) -> Result<Triage, TriageError> {
    run_child_process_with(Path::new(PROC_STATUS), command, bytes, limits, (grace_millis, plumbing))
}


/// `run_child_process` with the status file that tells whether SIGCHLD is ignored injected.
pub fn run_child_process_with(
    status: &Path,
    mut command: Command,
    bytes: Vec<u8>,
    limits: &Limits,
    timing: (u64, (ReadFn, SpawnFn, GroupKillFn)),
) -> Result<Triage, TriageError> {
    let (grace_millis, plumbing) = timing;
    require_waitable(status)?;
    let profile: Option<(OsString, OsString)> = std::env::var_os(PROFILE_VARIABLE).map(|value| (OsString::from(PROFILE_VARIABLE), value));
    command
        .env_clear()
        .envs(profile)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(NEW_PROCESS_GROUP);
    let mut child = command.spawn().map_err(|error| {
        let kind = format!("{:?}", error.kind());
        warn!(kind, "the child did not start");
        TriageError::ChildFailed
    })?;
    let pid = Pid::from_child(&child);
    let collected = child
        .stdin
        .take()
        .zip(child.stdout.take())
        .map_or(Err(TriageError::ChildFailed), |(stdin, stdout)| {
            converse((stdin, stdout), bytes, limits, (plumbing.0, plumbing.1))
        });
    match collected {
        Ok(output) => settle(pid, &mut child, &output, (grace_millis, plumbing.2)),
        Err(error) => stop(pid, &mut child, error, plumbing.2),
    }
}
