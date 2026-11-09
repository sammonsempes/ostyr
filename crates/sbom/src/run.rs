//! Runs syft on an operator-given target and parses its CycloneDX output while it streams (Unix only: process groups).

use crate::error::{RunError, SbomError};
use crate::limits::{HELPERS_PER_RUN, HOME_PREFIX, REAP_POLL_MILLIS, STDERR_EXCERPT_BYTES, SYFT_ARGUMENTS};
use crate::model::{Limits, Sbom, Stderr};
use crate::parse::{parse_cyclonedx, to_u64};
use crate::settings::{ensure, source_argument, validate_settings, SyftSettings, Target};
use crate::types::{Helpers, Job};
use rustix::io::Errno;
use rustix::process::{kill_process, kill_process_group, Pid, Signal};
use std::ffi::OsString;
use std::fs;
use std::io::{self, PipeReader, PipeWriter, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SendError};
use std::thread;
use std::time::Duration;
use tracing::debug;


/// One live helper thread; the count drops when it ends, so a run refuses to start while earlier helpers are still stuck.
pub struct HelperSlot(pub Helpers);


impl Drop for HelperSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}


/// Reserves the helpers of one run, or `None` when `max_live` would be exceeded.
pub fn reserve_helpers(helpers: &Helpers, max_live: usize) -> Option<[HelperSlot; HELPERS_PER_RUN]> {
    helpers
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
            live.checked_add(HELPERS_PER_RUN).filter(|total| *total <= max_live)
        })
        .ok()
        .map(|_| [HelperSlot(helpers.clone()), HelperSlot(helpers.clone())])
}


pub const NEW_PROCESS_GROUP: i32 = 0;


/// The only variables the child sees: no proxy, no update check, a private home and cache.
pub fn child_environment(home: &Path) -> Vec<(String, String)> {
    let home_text = home.to_string_lossy().into_owned();
    ["HOME", "XDG_CACHE_HOME", "SYFT_CACHE_DIR", "TMPDIR"]
        .into_iter()
        .map(|name| (name.to_owned(), home_text.clone()))
        .chain(std::iter::once(("SYFT_CHECK_FOR_APP_UPDATE".to_owned(), "false".to_owned())))
        .collect()
}


/// Keeps at most `cap` bytes and counts, without buffering, what comes after.
pub fn drain_stderr<Source: Read>(mut source: Source, cap: usize) -> io::Result<Stderr> {
    let mut kept = Vec::new();
    io::copy(&mut source.by_ref().take(to_u64(cap)), &mut kept)?;
    let dropped = io::copy(&mut source, &mut io::sink())?;
    let total = to_u64(kept.len()).saturating_add(dropped);
    Ok(Stderr { kept, total })
}


/// A bounded, escaped excerpt: control characters never reach a log line raw.
pub fn stderr_excerpt(stderr: &Stderr) -> String {
    let head: Vec<u8> = stderr.kept.iter().copied().take(STDERR_EXCERPT_BYTES).collect();
    String::from_utf8_lossy(&head).escape_debug().to_string()
}


/// Kills the child by pid (it may have left its group) and its group; a missing group is expected and only logged.
pub fn kill_all(pid: Pid) -> Result<(), Errno> {
    let _group = kill_process_group(pid, Signal::KILL).inspect_err(|error| debug!(error = ?error, "no process group to kill"));
    kill_process(pid, Signal::KILL)
}


/// Kills the process group when `done` does not close before the deadline; `true` means it did.
pub fn watchdog(pid: Pid, done: &Receiver<()>, deadline: Duration) -> Result<bool, Errno> {
    match done.recv_timeout(deadline) {
        Err(RecvTimeoutError::Timeout) => kill_all(pid).map(|()| true),
        _ => Ok(false),
    }
}


fn check_binary(binary: &Path) -> Result<(), RunError> {
    ensure(fs::metadata(binary)?.is_file(), RunError::NotRegular)
}


fn spawn_syft(settings: &SyftSettings, source: &str, home: &Path, stdout: PipeWriter, stderr: PipeWriter) -> io::Result<Child> {
    let mut command = Command::new(&settings.binary);
    command
        .args(SYFT_ARGUMENTS)
        .arg(source)
        .env_clear()
        .envs(
            child_environment(home)
                .into_iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        )
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .process_group(NEW_PROCESS_GROUP);
    command.spawn()
}


/// Runs one helper job and logs a result that nobody waited for.
pub fn run_job(job: Job) {
    if let Err(error) = job() {
        debug!(error = ?error, "syft helper result was not collected");
    }
}


/// Starts a named-less helper thread; a failed spawn is an error, never a panic.
pub fn spawn_thread(job: Job) -> io::Result<()> {
    thread::Builder::new().spawn(move || run_job(job)).map(|_handle| ())
}


impl<Value> From<SendError<Value>> for RunError {
    fn from(_error: SendError<Value>) -> Self {
        Self::Abandoned
    }
}


/// Starts every job in order; the first failed spawn drops the jobs not yet started.
pub fn start_jobs<Spawn: FnMut(Job) -> io::Result<()>>(jobs: Vec<Job>, spawner: Spawn) -> io::Result<()> {
    jobs.into_iter().try_for_each(spawner)
}


/// Waits for the child in bounded polls; `None` when it is still running after `polls` of `REAP_POLL_MILLIS`.
pub fn reap(child: &mut Child, polls: u64) -> io::Result<Option<ExitStatus>> {
    (0..polls)
        .find_map(|_| match child.try_wait() {
            Ok(None) => {
                thread::sleep(Duration::from_millis(REAP_POLL_MILLIS));
                None
            }
            other => Some(other),
        })
        .unwrap_or(Ok(None))
}


/// Runs syft with the given settings snapshot on `target` and returns its parsed SBOM for `tenant` and `artefact`.
pub fn generate(settings: &SyftSettings, helpers: &Helpers, target: &Target, tenant: &str, artefact: &str) -> Result<Sbom, RunError> {
    generate_with(spawn_thread, settings, helpers, target, (tenant, artefact))
}


/// `generate` with an injected thread spawner.
pub fn generate_with<Spawn: FnMut(Job) -> io::Result<()>>(
    spawner: Spawn,
    settings: &SyftSettings,
    helpers: &Helpers,
    target: &Target,
    scope: (&str, &str),
) -> Result<Sbom, RunError> {
    validate_settings(settings)?;
    let source = source_argument(target)?;
    check_binary(&settings.binary)?;
    let slots = reserve_helpers(helpers, settings.max_live_helpers).ok_or(RunError::Busy)?;
    let home = tempfile::Builder::new().prefix(HOME_PREFIX).tempdir_in(&settings.work_dir)?;
    let (stdout_reader, stdout_writer) = io::pipe()?;
    let (stderr_reader, stderr_writer) = io::pipe()?;
    let child = spawn_syft(settings, &source, home.path(), stdout_writer, stderr_writer)?;
    supervise(spawner, settings, child, (stdout_reader, stderr_reader), scope, slots)
}


/// What the stderr helper left, as one log text: size and a bounded escaped excerpt, or why there is none.
pub fn stderr_summary(result: &Result<io::Result<Stderr>, RecvTimeoutError>) -> String {
    match result {
        Ok(Ok(stderr)) => format!("{} bytes, excerpt `{}`", stderr.total, stderr_excerpt(stderr)),
        Ok(Err(error)) => format!("unreadable: {error}"),
        Err(_) => "still held open past the grace".to_owned(),
    }
}


/// Typed outcome: timeout first (a silent helper counts), then a syft that failed on its own (code and parse error kept), then the parse error.
pub fn outcome(timed_out: bool, parsed: Result<Result<Sbom, SbomError>, RecvTimeoutError>, exit: ExitStatus) -> Result<Sbom, RunError> {
    let own_failure = exit.code().filter(|code| *code != 0);
    match (timed_out, parsed) {
        (true, _) | (_, Err(_)) => Err(RunError::TimedOut),
        (false, Ok(Ok(sbom))) if exit.success() => Ok(sbom),
        (false, Ok(Ok(_))) => Err(RunError::Failed {
            code: exit.code(),
            source: None,
        }),
        (false, Ok(Err(error))) => Err(match (own_failure, &error) {
            (Some(code), SbomError::Json(_) | SbomError::Read(_)) => RunError::Failed {
                code: Some(code),
                source: Some(error),
            },
            _ => error.into(),
        }),
    }
}


pub fn supervise<Spawn: FnMut(Job) -> io::Result<()>>(
    spawner: Spawn,
    settings: &SyftSettings,
    mut child: Child,
    pipes: (PipeReader, PipeReader),
    scope: (&str, &str),
    slots: [HelperSlot; HELPERS_PER_RUN],
) -> Result<Sbom, RunError> {
    let (stdout_reader, stderr_reader) = pipes;
    let [stdout_slot, stderr_slot] = slots;
    let pid = Pid::from_child(&child);
    let deadline = Duration::from_millis(settings.deadline_millis);
    let grace = Duration::from_millis(settings.helper_grace_millis);
    let polls = settings.helper_grace_millis / REAP_POLL_MILLIS + 1;
    let (done_sender, done_receiver) = mpsc::channel::<()>();
    let (watch_sender, watch_receiver) = mpsc::channel();
    let (stderr_sender, stderr_receiver) = mpsc::channel();
    let (parse_sender, parse_receiver) = mpsc::channel();
    let stderr_cap = settings.max_stderr_bytes;
    let limits = Limits {
        max_bytes: settings.max_stdout_bytes,
        max_components: settings.max_components,
        ..Limits::default()
    };
    let (tenant, artefact) = (scope.0.to_owned(), scope.1.to_owned());
    let jobs: Vec<Job> = vec![
        Box::new(move || watch_sender.send(watchdog(pid, &done_receiver, deadline)).map_err(RunError::from)),
        Box::new(move || {
            let drained = drain_stderr(stderr_reader, stderr_cap);
            drop(stderr_slot);
            stderr_sender.send(drained).map_err(RunError::from)
        }),
        Box::new(move || {
            let parsed = parse_cyclonedx(stdout_reader, &tenant, &artefact, &limits);
            drop(stdout_slot);
            parse_sender.send(parsed).map_err(RunError::from)
        }),
    ];
    let started = start_jobs(jobs, spawner);
    let parsed = parse_receiver.recv_timeout(deadline.saturating_add(grace));
    drop(done_sender);
    let watched = watch_receiver.recv();
    let stopped = match &parsed {
        Ok(Ok(_)) => Ok(()),
        _ => kill_all(pid),
    };
    let first = reap(&mut child, polls);
    let exit = match &first {
        Ok(None) => kill_all(pid)
            .map_err(RunError::from)
            .and_then(|()| reap(&mut child, polls).map_err(RunError::from)),
        _ => first.map_err(RunError::from),
    };
    started?;
    let timed_out = watched??;
    stopped?;
    let status = exit?.ok_or(RunError::Unreaped)?;
    let summary = stderr_summary(&stderr_receiver.recv_timeout(grace));
    debug!(%summary, "syft finished");
    outcome(timed_out, parsed, status)
}
