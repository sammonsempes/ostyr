use crate::code_dir::{copy_package, CodeDir, GATE_NAME};
use crate::error::ConnectorError;
use crate::kill::{kill_leaf, KillHost};
use crate::model::{Runtime, Verified};
use crate::package::io_at;
use crate::reply::{parse_reply, Reply, MAX_REPLY_BYTES};
use crate::scan::errno_error;
use crate::types::{LaunchFn, NamerFn, SpawnFn, Started};
use core_config::trusted_dir::open_trusted_dir;
use rustix::fs::{statat, AtFlags, FileType};
use rustix::process::{getegid, geteuid, getgroups};
use script_library::cgroup::{create_cgroup, CgroupOps};
use script_library::launch::check_run_as;
use script_library::model::{Limits, RunAs};
use serde_json::value::RawValue;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};


pub const MAX_REQUEST_BYTES: usize = 1_048_576;


pub const MAX_STDERR_BYTES: u64 = 65_536;


pub const MAX_EVENTS: usize = 1_000_000;


pub const DRAIN_SECONDS: u64 = 5;


pub const MAX_DEADLINE_SECONDS: u64 = 3_600;


pub const GATE_RELEASE: &[u8] = b"\n";


pub const ROOT_UID: u32 = 0;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const SHELL_PATH: &str = "/bin/sh";


pub const PRLIMIT_PATH: &str = "/usr/bin/prlimit";


pub const PYTHON_PATH: &str = "/usr/bin/python3";


pub const PRLIMIT_ARGUMENTS: [&str; 5] = ["--as=8589934592", "--cpu=600", "--fsize=67108864", "--nofile=256", "--core=0"];


pub const PYTHON_ARGUMENTS: [&str; 2] = ["-I", "-B"];


/// The program chain of a run: the gate shell, `prlimit` and the connector's runtime.
#[derive(Debug, Clone)]
pub struct Programs {
    pub shell: PathBuf,
    pub prlimit: PathBuf,
    pub python: PathBuf,
}


/// The argument vector and the user of a run; the injected launcher wraps it (the privilege drop is its job) and returns the command.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub argv: Vec<OsString>,
    pub run_as: RunAs,
    pub directory: PathBuf,
}


/// Everything the run needs that tests replace.
#[derive(Debug, Clone)]
pub struct RunHost {
    pub launch: LaunchFn,
    pub spawn: SpawnFn,
    pub kill: KillHost,
    pub cgroup: CgroupOps,
    pub namer: NamerFn,
    pub programs: Programs,
    pub runner_uid: u32,
}


#[derive(Debug)]
pub struct RunSpec<'a> {
    pub verified: &'a Verified,
    pub package: &'a Path,
    pub code_root: &'a Path,
    pub cgroup_root: &'a Path,
    pub run_as: RunAs,
    pub limits: Limits,
    pub deadline: Duration,
    pub action: &'a str,
    pub params: &'a RawValue,
}


/// Bytes read from the connector's stderr and whether they passed the kept budget; the bytes themselves are dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StderrReport {
    pub bytes: u64,
    pub cut: bool,
}


#[derive(Debug)]
pub struct RunOutcome {
    pub reply: Reply,
    pub stderr: StderrReport,
}


#[derive(Debug)]
pub enum Event {
    Overflow,
    Stdout(io::Result<Vec<u8>>),
    Stderr(io::Result<StderrReport>),
    Stdin(io::Result<()>),
    Exit(io::Result<ExitStatus>),
}


#[derive(Debug)]
pub enum Cause {
    Timeout,
    Overflow,
    Pipe(io::Error),
}


#[derive(Debug, Default)]
pub struct Gathered {
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<StderrReport>,
    pub stdin_done: bool,
    pub exit: Option<Option<ExitStatus>>,
    pub cause: Option<Cause>,
}


pub fn spawn_piped(command: &mut Command) -> io::Result<Child> {
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
}


/// The checked kind of a program file: a regular file owned by the trusted user and not writable by group or others.
pub fn check_program(path: &Path, trusted_uid: u32) -> Result<(), ConnectorError> {
    let label = path.display().to_string();
    let resolved = std::fs::canonicalize(path).map_err(io_at(&label))?;
    let (parent, name) = resolved
        .parent()
        .zip(resolved.file_name())
        .ok_or(ConnectorError::Invalid { field: "program" })?;
    let directory = open_trusted_dir(parent, trusted_uid)?;
    let stat = statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(errno_error(&label))?;
    (FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_uid == trusted_uid && stat.st_mode & GROUP_OTHER_WRITE == 0)
        .then_some(())
        .ok_or(ConnectorError::Invalid { field: "program" })
}


pub fn check_programs(spec: &RunSpec<'_>, host: &RunHost) -> Result<(), ConnectorError> {
    let runtime = match spec.verified.manifest.runtime {
        Runtime::Native => None,
        Runtime::Python3 => Some(&host.programs.python),
    };
    [&host.programs.shell, &host.programs.prlimit]
        .into_iter()
        .chain(runtime)
        .try_for_each(|program| check_program(program, ROOT_UID))
}


/// A dedicated user only: never root, never the caller's own ids or groups.
pub fn check_run_user(run_as: RunAs) -> Result<(), ConnectorError> {
    let groups: Vec<u32> = getgroups()
        .map_err(io::Error::from)
        .map_err(ConnectorError::Pipe)?
        .iter()
        .map(|group| group.as_raw())
        .collect();
    Ok(check_run_as(Some(&run_as), geteuid().as_raw(), getegid().as_raw(), &groups)?)
}


/// `{"action": <name>, "params": <value>}` and a newline; the action is a manifest name (ASCII grammar), the params are raw JSON text already.
pub fn build_request(spec: &RunSpec<'_>) -> Result<Vec<u8>, ConnectorError> {
    spec.verified
        .manifest
        .actions
        .iter()
        .any(|action| action.name == spec.action)
        .then_some(())
        .ok_or_else(|| ConnectorError::UnknownAction {
            action: spec.action.chars().take(crate::scan::MAX_SHOWN_NAME_CHARS).collect(),
        })?;
    let text = format!("{{\"action\":\"{}\",\"params\":{}}}\n", spec.action, spec.params.get());
    (text.len() <= MAX_REQUEST_BYTES)
        .then(|| text.into_bytes())
        .ok_or(ConnectorError::RequestTooLarge { max: MAX_REQUEST_BYTES })
}


/// The argument vector: the gate shell script, `prlimit`, then the entry by path (native) or the interpreter in isolated mode with the entry (`python3`).
pub fn launch_plan(spec: &RunSpec<'_>, host: &RunHost, code: &CodeDir) -> LaunchPlan {
    let entry = code.path.join(&spec.verified.manifest.entry);
    let runtime: Vec<OsString> = match spec.verified.manifest.runtime {
        Runtime::Native => vec![entry.into_os_string()],
        Runtime::Python3 => std::iter::once(host.programs.python.clone().into_os_string())
            .chain(PYTHON_ARGUMENTS.iter().map(OsString::from))
            .chain(std::iter::once(entry.into_os_string()))
            .collect(),
    };
    let argv = [host.programs.shell.clone().into_os_string(), code.path.join(GATE_NAME).into_os_string()]
        .into_iter()
        .chain(std::iter::once(host.programs.prlimit.clone().into_os_string()))
        .chain(PRLIMIT_ARGUMENTS.iter().map(OsString::from))
        .chain(runtime)
        .collect();
    LaunchPlan {
        argv,
        run_as: spec.run_as,
        directory: code.path.clone(),
    }
}


/// Kills the whole cgroup when dropped, so an error path never leaves a process behind.
pub struct Reaper<'a> {
    pub host: &'a KillHost,
    pub leaf: BorrowedFd<'a>,
    pub run_uid: u32,
}


impl Drop for Reaper<'_> {
    fn drop(&mut self) {
        let result = kill_leaf(self.host, self.leaf, self.run_uid);
        if let Err(error) = result {
            let text = error.to_string();
            log::error!("the run cgroup could not be emptied: {text}");
        }
    }
}


/// A kill or a reap that failed is logged by its kind only.
pub fn log_reaping(killed: io::Result<()>, waited: io::Result<ExitStatus>) {
    if let Err(error) = killed {
        log::warn!("an abandoned child could not be killed: {:?}", error.kind());
    }
    if let Err(error) = waited {
        log::warn!("an abandoned child could not be reaped: {:?}", error.kind());
    }
}


/// A child that never got to run: killed and reaped, the cause is reported.
pub fn abandon(mut child: Child, cause: io::Error) -> ConnectorError {
    let killed = child.kill();
    log_reaping(killed, child.wait());
    ConnectorError::Pipe(cause)
}


pub fn send_event(sender: &Sender<Event>, event: Event) {
    if sender.send(event).is_err() {
        log::warn!("an event of a finished run was dropped");
    }
}


/// Reads at most `cap + 1` bytes: one more is an overflow, reported at once, and the rest of the stream is read and thrown away so the child never blocks on a full pipe.
pub fn pump_stdout(source: &mut dyn Read, cap: usize, send: &mut dyn FnMut(Event)) {
    let mut bytes = Vec::new();
    let read = Read::take(&mut *source, cap as u64 + 1).read_to_end(&mut bytes);
    let overflow = read.is_ok() && bytes.len() > cap;
    if overflow {
        send(Event::Overflow);
        bytes.clear();
    }
    if let Err(error) = io::copy(source, &mut io::sink()) {
        log::warn!("the stdout drain failed: {:?}", error.kind());
    }
    send(Event::Stdout(read.map(|_| bytes)));
}


/// Counted and dropped: stderr may echo a credential, so it is never kept or logged.
pub fn pump_stderr(source: &mut dyn Read, send: &mut dyn FnMut(Event)) {
    let copied = io::copy(source, &mut io::sink());
    send(Event::Stderr(copied.map(|bytes| StderrReport {
        bytes,
        cut: bytes > MAX_STDERR_BYTES,
    })));
}


/// The gate byte, then the request; a closed pipe after the kill is not an error.
pub fn pump_stdin(sink: &mut dyn Write, request: &[u8], send: &mut dyn FnMut(Event)) {
    let written = sink
        .write_all(GATE_RELEASE)
        .and_then(|()| sink.write_all(request))
        .and_then(|()| sink.flush())
        .or_else(|error| if error.kind() == io::ErrorKind::BrokenPipe { Ok(()) } else { Err(error) });
    send(Event::Stdin(written));
}


pub fn failed(state: Gathered, error: io::Error) -> Gathered {
    Gathered {
        cause: state.cause.or(Some(Cause::Pipe(error))),
        ..state
    }
}


pub fn apply(state: Gathered, event: Event) -> Gathered {
    match event {
        Event::Overflow => Gathered {
            cause: state.cause.or(Some(Cause::Overflow)),
            ..state
        },
        Event::Stdout(Ok(bytes)) => Gathered {
            stdout: Some(bytes),
            ..state
        },
        Event::Stdout(Err(error)) => failed(
            Gathered {
                stdout: Some(Vec::new()),
                ..state
            },
            error,
        ),
        Event::Stderr(Ok(report)) => Gathered {
            stderr: Some(report),
            ..state
        },
        Event::Stderr(Err(error)) => failed(
            Gathered {
                stderr: Some(StderrReport::default()),
                ..state
            },
            error,
        ),
        Event::Stdin(Ok(())) => Gathered { stdin_done: true, ..state },
        Event::Stdin(Err(error)) => failed(Gathered { stdin_done: true, ..state }, error),
        Event::Exit(Ok(status)) => Gathered {
            exit: Some(Some(status)),
            ..state
        },
        Event::Exit(Err(error)) => failed(Gathered { exit: Some(None), ..state }, error),
    }
}


pub fn complete(state: &Gathered) -> bool {
    state.stdout.is_some() && state.stderr.is_some() && state.stdin_done && state.exit.is_some()
}


/// Events until every stream and the exit are in, a cause is set (when `stop_on_cause`), or the limit passes; the loop is capped.
pub fn gather(events: &Receiver<Event>, state: Gathered, limit: Instant, stop_on_cause: bool) -> Gathered {
    (0..MAX_EVENTS)
        .try_fold(state, |current, _step| {
            if complete(&current) || (stop_on_cause && current.cause.is_some()) {
                Err(current)
            } else {
                match events.recv_timeout(limit.saturating_duration_since(Instant::now())) {
                    Ok(event) => Ok(apply(current, event)),
                    Err(_expired) => Err(Gathered {
                        cause: current.cause.or(Some(Cause::Timeout)),
                        ..current
                    }),
                }
            }
        })
        .unwrap_or_else(|finished| finished)
}


/// A cause wins over the exit status; a clean exit is read as the reply grammar, anything else refuses the reply.
pub fn verdict(state: Gathered) -> Result<RunOutcome, ConnectorError> {
    match (state.cause, state.exit.flatten(), state.stdout, state.stderr) {
        (Some(Cause::Overflow), ..) => Err(ConnectorError::ReplyTooLarge { max: MAX_REPLY_BYTES }),
        (Some(Cause::Timeout), ..) => Err(ConnectorError::RunTimeout),
        (Some(Cause::Pipe(error)), ..) => Err(ConnectorError::Pipe(error)),
        (None, Some(status), Some(bytes), Some(stderr)) if status.success() => parse_reply(&bytes).map(|reply| RunOutcome { reply, stderr }),
        (None, Some(status), Some(_), Some(_)) => Err(ConnectorError::RunFailed { code: status.code() }),
        (None, ..) => Err(ConnectorError::RunTimeout),
    }
}


/// Spawns the gated child and puts it in the leaf before the gate is released: the child reads the release byte only after the placement.
pub fn start_child(host: &RunHost, plan: &LaunchPlan, leaf: BorrowedFd<'_>) -> Result<Started, ConnectorError> {
    let mut command = (host.launch)(plan);
    command.env_clear().current_dir(&plan.directory);
    let mut child = (host.spawn)(&mut command).map_err(ConnectorError::Launch)?;
    match (child.stdin.take(), child.stdout.take(), child.stderr.take()) {
        (Some(stdin), Some(stdout), Some(stderr)) => match (host.cgroup.place)(leaf, child.id()) {
            Ok(()) => Ok((child, stdin, stdout, stderr)),
            Err(error) => Err(abandon(child, error)),
        },
        _ => Err(abandon(child, io::Error::other("the child has no pipes"))),
    }
}


/// Copies the signed package, runs it in its own cgroup as the run user, and returns the checked reply.
pub fn run_connector(spec: &RunSpec<'_>, host: &RunHost) -> Result<RunOutcome, ConnectorError> {
    let request = build_request(spec)?;
    check_run_user(spec.run_as)?;
    check_programs(spec, host)?;
    let code = copy_package(spec.verified, spec.package, spec.code_root, host.runner_uid, host.namer)?;
    let guard = create_cgroup(spec.cgroup_root, &code.name, host.cgroup.check)?;
    (host.cgroup.limit)(guard.leaf.as_fd(), &spec.limits).map_err(ConnectorError::Pipe)?;
    let reaper = Reaper {
        host: &host.kill,
        leaf: guard.leaf.as_fd(),
        run_uid: spec.run_as.uid,
    };
    let plan = launch_plan(spec, host, &code);
    let started_at = Instant::now();
    let limit = started_at + spec.deadline.min(Duration::from_secs(MAX_DEADLINE_SECONDS));
    let (mut child, mut stdin, mut stdout, mut stderr) = start_child(host, &plan, reaper.leaf)?;
    let (sender, events) = channel::<Event>();
    let on_stdin = sender.clone();
    let on_stdout = sender.clone();
    let on_stderr = sender.clone();
    let on_exit = sender.clone();
    thread::spawn(move || pump_stdin(&mut stdin, &request, &mut |event| send_event(&on_stdin, event)));
    thread::spawn(move || pump_stdout(&mut stdout, MAX_REPLY_BYTES, &mut |event| send_event(&on_stdout, event)));
    thread::spawn(move || pump_stderr(&mut stderr, &mut |event| send_event(&on_stderr, event)));
    thread::spawn(move || send_event(&on_exit, Event::Exit(child.wait())));
    let waited = gather(&events, Gathered::default(), limit, true);
    kill_leaf(&host.kill, reaper.leaf, spec.run_as.uid)?;
    let finished = gather(&events, waited, Instant::now() + Duration::from_secs(DRAIN_SECONDS), false);
    verdict(finished)
}
