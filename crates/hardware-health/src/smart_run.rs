//! Discovers disks with `smartctl --scan-open` and reads each with `smartctl -a` (Unix only: process groups).

use crate::limits::{default_limits, MAX_DEADLINE_SECONDS, MAX_DEVICE_NAME_BYTES, MAX_DEVICE_TYPE_BYTES, MAX_SCAN_BYTES, MAX_SCAN_DEVICES};
use crate::model::{FailureClass, RunOutput, RunReport, SmartReport, SmartSettings};
use crate::parse::parse_smartctl;
use crate::smart_exec::{check_program_as, check_unchanged};
use crate::types::{ClockFn, RunnerFn};
use net_topology::model::RunFailure;
use net_topology::runner::{read_output, reap_killed, sigchld_ignored, wait_exit, PROC_STATUS};
use rustix::process::geteuid;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{debug, warn};


const QUOTES: usize = 2;


pub const SCAN_ARGUMENTS: [&str; 2] = ["--scan-open", "--json=c"];


pub const DEVICE_PREFIX: [&str; 3] = ["--json=c", "-a", "-d"];


pub const DEVICE_ROOT: &str = "/dev/";


pub const EXIT_COMMAND_LINE: i32 = 1;


pub const EXIT_OPEN_FAILED: i32 = 2;


pub const NEW_PROCESS_GROUP: i32 = 0;


pub const FIXED_ENVIRONMENT: [(&str, &str); 1] = [("LC_ALL", "C")];


#[derive(Deserialize)]
struct Counted {
    #[serde(default)]
    devices: Vec<IgnoredAny>,
}


#[derive(Deserialize)]
struct Scan {
    #[serde(default)]
    devices: Vec<Box<RawValue>>,
}


#[derive(Deserialize)]
struct ScanEntry {
    #[serde(default)]
    name: Option<Box<RawValue>>,
    #[serde(default, rename = "type")]
    kind: Option<Box<RawValue>>,
}


/// `/dev/` then `[a-z0-9/_-]`, no `//`, at most `MAX_DEVICE_NAME_BYTES`.
pub fn is_device_name(text: &str) -> bool {
    let body = text.strip_prefix(DEVICE_ROOT).unwrap_or("");
    !body.is_empty()
        && text.len() <= MAX_DEVICE_NAME_BYTES
        && !text.contains("//")
        && body
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"/_-".contains(&byte))
}


/// `[a-z0-9,_+-]`, at most `MAX_DEVICE_TYPE_BYTES`, never starting with `-`.
pub fn is_device_type(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_DEVICE_TYPE_BYTES
        && !text.starts_with('-')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b",_+-".contains(&byte))
}


/// Bits 0 and 1 of the exit status are a failed run; bits 2 to 7 still carry a parseable report; no code means a signal.
pub fn classify_exit(code: Option<i32>) -> Option<FailureClass> {
    match code {
        None => Some(FailureClass::Signalled),
        Some(status) if status & EXIT_COMMAND_LINE != 0 => Some(FailureClass::CommandLine),
        Some(status) if status & EXIT_OPEN_FAILED != 0 => Some(FailureClass::OpenFailed),
        Some(_) => None,
    }
}


pub fn failure_of(failure: RunFailure) -> FailureClass {
    match failure {
        RunFailure::TimedOut => FailureClass::TimedOut,
        RunFailure::TooLarge => FailureClass::TooLarge,
        RunFailure::Spawn => FailureClass::Spawn,
        RunFailure::Unwaitable => FailureClass::Unwaitable,
        RunFailure::Failed { .. } | RunFailure::Io | RunFailure::Refused => FailureClass::Io,
    }
}


impl From<io::Error> for FailureClass {
    fn from(error: io::Error) -> Self {
        let kind = error.kind();
        debug!(?kind, "smartctl run failed on an I/O error");
        Self::Io
    }
}


fn spawn_failure(error: io::Error) -> FailureClass {
    let kind = error.kind();
    debug!(?kind, "smartctl could not be started");
    FailureClass::Spawn
}


fn spawn(program: &Path, arguments: &[&str], stdout: io::PipeWriter) -> io::Result<Child> {
    Command::new(program)
        .args(arguments)
        .env_clear()
        .envs(FIXED_ENVIRONMENT)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::null())
        .process_group(NEW_PROCESS_GROUP)
        .spawn()
}


fn finish(child: &mut Child, bytes: Vec<u8>, until: Instant) -> Result<RunOutput, FailureClass> {
    let status = wait_exit(child, until, &mut Instant::now)
        .map_err(failure_of)?
        .ok_or(FailureClass::TimedOut)?;
    Ok(RunOutput {
        bytes,
        exit_code: status.code(),
    })
}


/// The default hook between the check and the spawn: nothing.
pub fn leave_alone(_program: &Path) {}


/// Runs `program` with `arguments` (environment cleared but `LC_ALL=C`, own process group, stdout capped at `cap`, stderr discarded) within `deadline`.
pub fn run_smartctl(program: &Path, arguments: &[&str], cap: u64, deadline: Duration) -> Result<RunOutput, FailureClass> {
    run_with_hook(program, arguments, (cap, deadline), (geteuid().as_raw(), leave_alone))
}


/// `run_smartctl` with the trusted uid and a hook that runs after the check and before the spawn, so both are testable.
pub fn run_with_hook(
    program: &Path,
    arguments: &[&str],
    (cap, deadline): (u64, Duration),
    (trusted_uid, between): (u32, fn(&Path)),
) -> Result<RunOutput, FailureClass> {
    let waitable = !sigchld_ignored(Path::new(PROC_STATUS)).map_err(failure_of)?;
    waitable.then_some(()).ok_or(FailureClass::Unwaitable)?;
    let judged = check_program_as(program, trusted_uid)?;
    between(program);
    check_unchanged(program, &judged, trusted_uid)?;
    let started = Instant::now();
    let until = started + deadline.min(Duration::from_secs(MAX_DEADLINE_SECONDS));
    let (mut reader, writer) = io::pipe()?;
    let mut child = spawn(program, arguments, writer).map_err(spawn_failure)?;
    let verdict = read_output(&mut reader, cap, until)
        .map_err(failure_of)
        .and_then(|bytes| finish(&mut child, bytes, until));
    if verdict.is_err() {
        reap_killed(&mut child, &mut Instant::now);
    }
    verdict
}


fn unparsable(error: serde_json::Error) -> FailureClass {
    let category = format!("{:?}", error.classify());
    debug!(category, "smartctl scan output refused");
    FailureClass::Unparsable
}


fn scan(settings: &SmartSettings, runner: RunnerFn, deadline: Duration) -> Result<Vec<Box<RawValue>>, FailureClass> {
    let output = runner(&settings.program, &SCAN_ARGUMENTS, MAX_SCAN_BYTES, deadline)?;
    classify_exit(output.exit_code).map_or(Ok(()), Err)?;
    let counted: Counted = serde_json::from_slice(&output.bytes).map_err(unparsable)?;
    let count = counted.devices.len();
    if count > MAX_SCAN_DEVICES {
        warn!(count, "the smartctl scan lists too many devices");
        Err(FailureClass::TooManyDevices)
    } else {
        let listing: Scan = serde_json::from_slice(&output.bytes).map_err(unparsable)?;
        Ok(listing.devices)
    }
}


fn one_device(settings: &SmartSettings, runner: RunnerFn, deadline: Duration, name: &str, kind: &str) -> Result<SmartReport, FailureClass> {
    let limits = default_limits();
    let arguments: Vec<&str> = DEVICE_PREFIX.iter().copied().chain([kind, name]).collect();
    let output = runner(&settings.program, &arguments, limits.max_bytes, deadline)?;
    classify_exit(output.exit_code).map_or(Ok(()), Err)?;
    parse_smartctl(output.bytes.as_slice(), &limits).map_err(|error| {
        debug!(%error, "smartctl output refused");
        FailureClass::Unparsable
    })
}


fn short_text(raw: Option<&RawValue>, cap: usize) -> Option<String> {
    let text = raw?.get();
    (text.starts_with('"') && text.len() <= cap + QUOTES)
        .then(|| serde_json::from_str::<String>(text).ok())
        .flatten()
}


fn entry_of(raw: &RawValue) -> Option<ScanEntry> {
    serde_json::from_str(raw.get()).map_or_else(
        |error: serde_json::Error| {
            let category = format!("{:?}", error.classify());
            debug!(category, "scan entry refused");
            None
        },
        Some,
    )
}


fn checked(raw: &RawValue) -> Option<(String, String)> {
    let entry = entry_of(raw)?;
    short_text(entry.name.as_deref(), MAX_DEVICE_NAME_BYTES)
        .filter(|name| is_device_name(name))
        .zip(short_text(entry.kind.as_deref(), MAX_DEVICE_TYPE_BYTES).filter(|kind| is_device_type(kind)))
}


struct Round {
    report: RunReport,
    spent: Duration,
}


/// The real monotonic clock.
pub fn system_clock(_settings: &SmartSettings) -> Instant {
    Instant::now()
}


fn read_device(settings: &SmartSettings, runner: RunnerFn, clock: ClockFn, mut round: Round, entry: (&str, &str)) -> Round {
    let (name, kind) = entry;
    let budget = Duration::from_secs(settings.round_deadline_seconds);
    let remaining = budget.saturating_sub(round.spent);
    if remaining.is_zero() {
        round.report.failed.push((name.to_owned(), FailureClass::Deferred));
    } else {
        let deadline = remaining.min(Duration::from_secs(settings.deadline_seconds));
        let started = clock(settings);
        let outcome = one_device(settings, runner, deadline, name, kind);
        round.spent += clock(settings).saturating_duration_since(started);
        match outcome {
            Ok(found) => round.report.reports.push((name.to_owned(), found)),
            Err(class) => round.report.failed.push((name.to_owned(), class)),
        }
    }
    round
}


/// Scans, then reads every accepted disk within the round budget; wall time of every run, the scan included, is charged and the scan gets `min(deadline, round)`; a disk past it is `Deferred`.
pub fn scan_and_report_with(settings: &SmartSettings, runner: RunnerFn, clock: ClockFn) -> RunReport {
    let deadline = Duration::from_secs(settings.deadline_seconds.min(settings.round_deadline_seconds));
    let started = clock(settings);
    let scanned = scan(settings, runner, deadline);
    let spent = clock(settings).saturating_duration_since(started);
    match scanned {
        Err(class) => RunReport {
            scan_failed: Some(class),
            ..RunReport::default()
        },
        Ok(entries) => {
            let start = Round {
                report: RunReport::default(),
                spent,
            };
            entries
                .iter()
                .fold(start, |mut round, raw| match checked(raw) {
                    None => {
                        round.report.refused_devices += 1;
                        round
                    }
                    Some((name, kind)) => read_device(settings, runner, clock, round, (&name, &kind)),
                })
                .report
        }
    }
}


/// `scan_and_report_with` on the real clock.
pub fn scan_and_report(settings: &SmartSettings, runner: RunnerFn) -> RunReport {
    scan_and_report_with(settings, runner, system_clock)
}
