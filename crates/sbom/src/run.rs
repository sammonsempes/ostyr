//! Runs syft on an operator-given target and parses its CycloneDX output while it streams (Unix only: process groups).

use crate::error::{ResourceKind, RunError, SbomError};
use crate::limits::{
    BLOCK_BYTES, DRAIN_CHUNK_BYTES, FILE_MARKERS, HELPERS_PER_RUN, HOME_PREFIX, MEMORY_MARKERS, REAP_POLL_MILLIS, STDERR_EXCERPT_BYTES,
    SYFT_ARGUMENTS,
};
use crate::model::{Limits, Sbom, Stderr, Verdict, WatchPlan};
use crate::parse::{parse_cyclonedx, to_u64};
use crate::settings::{ensure, source_argument, target_path, validate_settings, SyftSettings, Target};
use crate::types::{Helpers, Job};
use rustix::io::Errno;
use rustix::process::{kill_process, kill_process_group, Pid, Signal};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, PipeReader, PipeWriter, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SendError};
use std::thread;
use std::time::Duration;
use tracing::debug;
use walkdir::{DirEntry, WalkDir};


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


/// Keeps the last `cap` bytes (the cause of a failure comes last) and counts, without buffering, everything that came before.
pub fn drain_stderr(source: &mut dyn Read, cap: usize) -> io::Result<Stderr> {
    let mut chunks = std::iter::from_fn(|| {
        let mut chunk = Vec::new();
        match Read::take(&mut *source, DRAIN_CHUNK_BYTES).read_to_end(&mut chunk) {
            Ok(0) => None,
            Ok(_) => Some(Ok(chunk)),
            Err(error) => Some(Err(error)),
        }
    });
    let (tail, total) = chunks.try_fold((VecDeque::<u8>::new(), 0), |(mut tail, total): (VecDeque<u8>, u64), item| {
        let chunk = item?;
        let seen = total.saturating_add(to_u64(chunk.len()));
        tail.extend(chunk);
        let excess = tail.len().saturating_sub(cap);
        tail.drain(..excess);
        Ok::<_, io::Error>((tail, seen))
    })?;
    Ok(Stderr {
        kept: tail.into_iter().collect(),
        total,
    })
}


/// A bounded, escaped excerpt of the end of stderr: control characters never reach a log line raw.
pub fn stderr_excerpt(stderr: &Stderr) -> String {
    let skipped = stderr.kept.len().saturating_sub(STDERR_EXCERPT_BYTES);
    let tail: Vec<u8> = stderr.kept.iter().copied().skip(skipped).collect();
    String::from_utf8_lossy(&tail).escape_debug().to_string()
}


/// Kills the child by pid (it may have left its group) and its group; a missing group is expected and only logged.
pub fn kill_all(pid: Pid) -> Result<(), Errno> {
    let _group = kill_process_group(pid, Signal::KILL).inspect_err(|error| debug!(error = ?error, "no process group to kill"));
    kill_process(pid, Signal::KILL)
}


/// Kills the child and returns `verdict` (or its error) once it is dead.
pub fn kill_then(pid: Pid, verdict: Result<Verdict, RunError>) -> Result<Verdict, RunError> {
    kill_all(pid)?;
    verdict
}


/// One walk of the syft home: more entries than `max_entries` or more disk than `max_bytes` is `true`; the walk stops one entry past the cap.
pub fn disk_exceeded(home: &Path, max_bytes: u64, max_entries: usize) -> Result<bool, RunError> {
    let (count, bytes) = WalkDir::new(home)
        .into_iter()
        .take(max_entries.saturating_add(1))
        .try_fold((0, 0), |(count, bytes): (usize, u64), entry| {
            entry_bytes(entry).map(|size| (count + 1, bytes.saturating_add(size)))
        })?;
    Ok(count > max_entries || bytes > max_bytes)
}


/// Disk blocks used by one entry; an entry that vanished during the walk (syft deleting its temporary files) counts as nothing and is logged.
pub fn entry_bytes(entry: walkdir::Result<DirEntry>) -> Result<u64, RunError> {
    match entry.and_then(|found| found.metadata()) {
        Ok(metadata) => Ok(metadata.blocks().saturating_mul(BLOCK_BYTES)),
        Err(error) if error.io_error().is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound) => {
            let reason = format!("{error:?}");
            debug!(%reason, "entry vanished during the disk walk");
            Ok(0)
        }
        Err(error) => Err(error.into()),
    }
}


/// Ticks until `done` closes: at each tick the home size is checked, and the group is killed on a disk overrun or when the ticks run out.
pub fn watchdog(pid: Pid, done: &Receiver<()>, plan: &WatchPlan) -> Result<Verdict, RunError> {
    let decided = (0..plan.ticks).find_map(|_| match done.recv_timeout(plan.tick) {
        Err(RecvTimeoutError::Timeout) => match disk_exceeded(&plan.home, plan.max_bytes, plan.max_entries) {
            Ok(false) => None,
            Ok(true) => Some(kill_then(pid, Ok(Verdict::DiskFull))),
            Err(error) => Some(kill_then(pid, Err(error))),
        },
        _ => Some(Ok(Verdict::Finished)),
    });
    decided.unwrap_or_else(|| kill_then(pid, Ok(Verdict::TimedOut)))
}


/// The watchdog schedule: a tick of `disk_poll_millis` (shorter than the deadline) and enough ticks to cover the deadline.
pub fn watch_plan(settings: &SyftSettings, home: &Path) -> WatchPlan {
    let tick_millis = settings.disk_poll_millis.min(settings.deadline_millis).max(1);
    WatchPlan {
        home: home.to_path_buf(),
        tick: Duration::from_millis(tick_millis),
        ticks: settings.deadline_millis.div_ceil(tick_millis),
        max_bytes: settings.max_run_disk_bytes,
        max_entries: settings.max_run_entries,
    }
}


fn check_binary(binary: &Path) -> Result<(), RunError> {
    ensure(fs::metadata(binary)?.is_file(), RunError::NotRegular)
}


fn spawn_syft(settings: &SyftSettings, source: &str, home: &Path, stdout: PipeWriter, stderr: PipeWriter) -> io::Result<Child> {
    let mut command = Command::new(&settings.prlimit_binary);
    command
        .arg(format!("--as={}", settings.max_memory_bytes))
        .arg(format!("--fsize={}", settings.max_file_bytes))
        .arg("--")
        .arg(&settings.binary)
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


/// Refuses an archive target larger than `max`, measured on the opened handle (opened `O_NONBLOCK`, so a FIFO is refused, never waited on).
pub fn check_archive(target: &Target, max: u64) -> Result<(), RunError> {
    match target {
        Target::Directory(_) => Ok(()),
        Target::OciArchive(_) | Target::DockerArchive(_) => {
            let metadata = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(target_path(target))
                .and_then(|file| file.metadata())?;
            ensure(metadata.is_file(), RunError::NotRegular)?;
            ensure(
                metadata.len() <= max,
                RunError::ResourceLimit {
                    kind: ResourceKind::Archive,
                    cause: None,
                },
            )
        }
    }
}


/// Which resource limit a failed syft hit: SIGXFSZ, or a known out-of-memory or file-size message in the kept tail of its stderr (Go reports both as text).
pub fn exceeded_limit(exit: ExitStatus, stderr: &[u8]) -> Option<ResourceKind> {
    let text = String::from_utf8_lossy(stderr).to_lowercase();
    let mentions = |markers: &[&str]| markers.iter().any(|marker| text.contains(marker));
    match (exit.success(), exit.signal()) {
        (true, _) => None,
        (false, Some(libc::SIGXFSZ)) => Some(ResourceKind::FileSize),
        _ if mentions(&FILE_MARKERS) => Some(ResourceKind::FileSize),
        _ if mentions(&MEMORY_MARKERS) => Some(ResourceKind::Memory),
        _ => None,
    }
}


/// A resource limit hit replaces any other failure except a timeout; the replaced error stays as its cause.
pub fn classify(result: Result<Sbom, RunError>, limit: Option<ResourceKind>) -> Result<Sbom, RunError> {
    match (result, limit) {
        (Err(RunError::TimedOut), _) => Err(RunError::TimedOut),
        (Err(error), Some(kind)) => Err(RunError::ResourceLimit {
            kind,
            cause: Some(Box::new(error)),
        }),
        (other, _) => other,
    }
}


/// A disk overrun replaces whatever the killed run returned; that result stays as the cause.
pub fn disk_verdict(verdict: Verdict, result: Result<Sbom, RunError>) -> Result<Sbom, RunError> {
    match verdict {
        Verdict::DiskFull => Err(RunError::ResourceLimit {
            kind: ResourceKind::Disk,
            cause: result.err().map(Box::new),
        }),
        Verdict::Finished | Verdict::TimedOut => result,
    }
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
    check_binary(&settings.prlimit_binary)?;
    check_binary(&settings.binary)?;
    check_archive(target, settings.max_archive_bytes)?;
    let slots = reserve_helpers(helpers, settings.max_live_helpers).ok_or(RunError::Busy)?;
    let home = tempfile::Builder::new().prefix(HOME_PREFIX).tempdir_in(&settings.work_dir)?;
    let (stdout_reader, stdout_writer) = io::pipe()?;
    let (stderr_reader, stderr_writer) = io::pipe()?;
    let child = spawn_syft(settings, &source, home.path(), stdout_writer, stderr_writer)?;
    supervise(spawner, settings, (child, home.path()), (stdout_reader, stderr_reader), scope, slots)
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
    running: (Child, &Path),
    pipes: (PipeReader, PipeReader),
    scope: (&str, &str),
    slots: [HelperSlot; HELPERS_PER_RUN],
) -> Result<Sbom, RunError> {
    let (mut child, home) = running;
    let (stdout_reader, mut stderr_reader) = pipes;
    let [stdout_slot, stderr_slot] = slots;
    let pid = Pid::from_child(&child);
    let deadline = Duration::from_millis(settings.deadline_millis);
    let grace = Duration::from_millis(settings.helper_grace_millis);
    let polls = settings.helper_grace_millis / REAP_POLL_MILLIS + 1;
    let plan = watch_plan(settings, home);
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
        Box::new(move || watch_sender.send(watchdog(pid, &done_receiver, &plan)).map_err(RunError::from)),
        Box::new(move || {
            let drained = drain_stderr(&mut stderr_reader, stderr_cap);
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
    let verdict = watched??;
    stopped?;
    let status = exit?.ok_or(RunError::Unreaped)?;
    let stderr = stderr_receiver.recv_timeout(grace);
    let summary = stderr_summary(&stderr);
    debug!(%summary, "syft finished");
    let kept = stderr
        .as_ref()
        .ok()
        .and_then(|drained| drained.as_ref().ok())
        .map(|drained| drained.kept.as_slice());
    let limit = exceeded_limit(status, kept.unwrap_or(&[]));
    let result = classify(outcome(verdict == Verdict::TimedOut, parsed, status), limit);
    disk_verdict(verdict, result)
}
