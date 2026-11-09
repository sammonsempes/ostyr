//! Runs syft on an operator-given target and parses its CycloneDX output while it streams (Unix only: process groups).

use crate::error::{RunError, SbomError};
use crate::limits::{HELPERS_PER_RUN, HOME_PREFIX, STDERR_EXCERPT_BYTES, SYFT_ARGUMENTS};
use crate::model::{Limits, Sbom, Stderr};
use crate::parse::{parse_cyclonedx, to_u64};
use crate::settings::{ensure, source_argument, validate_settings, SyftSettings, Target};
use crate::types::Helpers;
use rustix::io::Errno;
use rustix::process::{kill_process_group, Pid, Signal};
use std::ffi::OsString;
use std::fs;
use std::io::{self, PipeReader, PipeWriter, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
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


pub fn kill_group(pid: Pid) -> Result<(), Errno> {
    kill_process_group(pid, Signal::KILL)
}


/// Kills the process group when `done` does not close before the deadline; `true` means it did.
pub fn watchdog(pid: Pid, done: &Receiver<()>, deadline: Duration) -> Result<bool, Errno> {
    match done.recv_timeout(deadline) {
        Err(RecvTimeoutError::Timeout) => kill_group(pid).map(|()| true),
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


/// Runs syft with the given settings snapshot on `target` and returns its parsed SBOM for `tenant` and `artefact`.
pub fn generate(settings: &SyftSettings, helpers: &Helpers, target: &Target, tenant: &str, artefact: &str) -> Result<Sbom, RunError> {
    validate_settings(settings)?;
    let source = source_argument(target)?;
    check_binary(&settings.binary)?;
    let slots = reserve_helpers(helpers, settings.max_live_helpers).ok_or(RunError::Busy)?;
    let home = tempfile::Builder::new().prefix(HOME_PREFIX).tempdir_in(&settings.work_dir)?;
    let (stdout_reader, stdout_writer) = io::pipe()?;
    let (stderr_reader, stderr_writer) = io::pipe()?;
    let child = spawn_syft(settings, &source, home.path(), stdout_writer, stderr_writer)?;
    supervise(settings, child, (stdout_reader, stderr_reader), (tenant, artefact), slots)
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


fn supervise(
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
    let (done_sender, done_receiver) = mpsc::channel();
    let (watch_sender, watch_receiver) = mpsc::channel();
    thread::spawn(move || watch_sender.send(watchdog(pid, &done_receiver, deadline)));
    let (stderr_sender, stderr_receiver) = mpsc::channel();
    let stderr_cap = settings.max_stderr_bytes;
    thread::spawn(move || {
        let drained = drain_stderr(stderr_reader, stderr_cap);
        drop(stderr_slot);
        stderr_sender.send(drained)
    });
    let limits = Limits {
        max_bytes: settings.max_stdout_bytes,
        max_components: settings.max_components,
        ..Limits::default()
    };
    let (parse_sender, parse_receiver) = mpsc::channel();
    let (tenant, artefact) = (scope.0.to_owned(), scope.1.to_owned());
    thread::spawn(move || {
        let parsed = parse_cyclonedx(stdout_reader, &tenant, &artefact, &limits);
        drop(stdout_slot);
        parse_sender.send(parsed)
    });
    let parsed = parse_receiver.recv_timeout(deadline.saturating_add(grace));
    let stopped = match &parsed {
        Ok(Ok(_)) => Ok(()),
        _ => kill_group(pid),
    };
    let status = child.wait();
    drop(done_sender);
    let timed_out = watch_receiver.recv()??;
    stopped?;
    let exit = status?;
    let summary = stderr_summary(&stderr_receiver.recv_timeout(grace));
    debug!(%summary, "syft finished");
    outcome(timed_out, parsed, exit)
}
