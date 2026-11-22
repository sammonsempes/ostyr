//! Restores one declared canary file from the newest snapshot of a declared host with `restic dump` and compares its SHA-256 (Unix only).

use crate::coverage::FUTURE_SKEW_SECONDS;
use crate::model::{Declarations, Limits, Listing, RepositoryFloor, ResticSource, RestoreTest, Snapshot};
use crate::parse::parse_restic;
use crate::restic::{
    command_arguments, config_id, password_failure, sftp_transport, unchanged, valid_path, valid_source, ResticError, CONFIG_CAP_BYTES, CONFIG_VERB,
    MAX_HOST_BYTES, MAX_LOCATION_BYTES, SNAPSHOTS_VERB,
};
use crate::text::{valid_id, valid_text};
use crate::types::{Clock, SkipCounts};
use core_config::secret_file::open_secret;
use core_pg::scope::TenantScope;
use net_topology::model::RunFailure;
use net_topology::runner::run_command;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, Instant};
use time::OffsetDateTime;


/// The only file name a restore test may read, so no other file of a backup is ever restored.
pub const CANARY_FILE_NAME: &str = ".ostyr-restore-canary";


pub const MAX_CANARY_BYTES: u64 = 1_048_576;


pub const DUMP_FLAGS: [&str; 3] = ["--no-cache", "--no-lock", "dump"];


/// One fixed outcome per test; only `Restored` is a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored,
    DigestMismatch,
    TooLarge,
    NotCovered,
    NoSnapshot,
    Failed { code: Option<i32> },
    Timeout,
    ListingGap { skipped: SkipCounts, future: u64 },
}


/// The lowercase name printed for an outcome.
pub fn outcome_label(outcome: &RestoreOutcome) -> &'static str {
    match outcome {
        RestoreOutcome::Restored => "restored",
        RestoreOutcome::DigestMismatch => "digest_mismatch",
        RestoreOutcome::TooLarge => "too_large",
        RestoreOutcome::NotCovered => "not_covered",
        RestoreOutcome::NoSnapshot => "no_snapshot",
        RestoreOutcome::Failed { .. } => "failed",
        RestoreOutcome::Timeout => "timeout",
        RestoreOutcome::ListingGap { .. } => "listing_gap",
    }
}


/// Never carries file bytes or a computed digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreResult {
    pub tenant: TenantScope,
    pub config_id: String,
    pub snapshot_id: Option<String>,
    pub snapshot_time: Option<OffsetDateTime>,
    pub tested_at: OffsetDateTime,
    pub outcome: RestoreOutcome,
}


/// The repositories whose restore test will run (declared name, source, test) and the indexes of the entries refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan<'a> {
    pub runnable: Vec<(&'a str, &'a ResticSource, &'a RestoreTest)>,
    pub refused: Vec<usize>,
}


/// An absolute path of at most `MAX_LOCATION_BYTES`, no empty or `.` component, whose last component is `CANARY_FILE_NAME`.
pub fn valid_canary_path(path: &str) -> bool {
    path.len() <= MAX_LOCATION_BYTES
        && valid_path(path)
        && path.split('/').skip(1).all(|component| !component.is_empty() && component != ".")
        && path.rsplit('/').next() == Some(CANARY_FILE_NAME)
}


pub fn valid_test(test: &RestoreTest) -> bool {
    valid_text(&test.host, MAX_HOST_BYTES)
        && valid_canary_path(&test.path)
        && valid_id(&test.sha256)
        && (1..=MAX_CANARY_BYTES).contains(&test.max_bytes)
}


fn candidate(entry: &RepositoryFloor) -> Option<(&ResticSource, &RestoreTest)> {
    entry
        .restic
        .as_ref()
        .zip(entry.restore_test.as_ref())
        .filter(|(source, test)| valid_source(source) && valid_test(test) && entry.borg.is_none())
}


/// Splits the entries that carry a `restore_test` into the runnable ones and the refused indexes; the other repositories are not affected.
pub fn restore_plan(declarations: &Declarations) -> RestorePlan<'_> {
    RestorePlan {
        runnable: declarations
            .repositories
            .iter()
            .filter_map(|entry| candidate(entry).map(|(source, test)| (entry.repository.as_str(), source, test)))
            .collect(),
        refused: declarations
            .repositories
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.restore_test.is_some() && candidate(entry).is_none())
            .map(|(index, _)| index)
            .collect(),
    }
}


/// The latest time a snapshot may carry: `now` plus `FUTURE_SKEW_SECONDS`.
pub fn horizon(now: OffsetDateTime) -> OffsetDateTime {
    now.checked_add(time::Duration::seconds(FUTURE_SKEW_SECONDS)).unwrap_or(now)
}


/// The newest snapshot of `host` not dated over `FUTURE_SKEW_SECONDS` after `now`, ties broken by the higher id.
pub fn choose<'a>(snapshots: &'a [Snapshot], host: &str, now: OffsetDateTime) -> Option<&'a Snapshot> {
    let horizon = horizon(now);
    snapshots
        .iter()
        .filter(|snapshot| snapshot.host.as_deref() == Some(host) && snapshot.time <= horizon)
        .max_by_key(|snapshot| (snapshot.time, snapshot.id.as_str()))
}


/// Fails closed: any skipped snapshot, or any snapshot of `host` dated in the future, makes the listing untrustworthy for the test.
pub fn listing_gap(listing: &Listing, host: &str, now: OffsetDateTime) -> Option<RestoreOutcome> {
    let limit = horizon(now);
    let future: u64 = listing
        .snapshots
        .iter()
        .filter(|snapshot| snapshot.host.as_deref() == Some(host) && snapshot.time > limit)
        .map(|_| 1)
        .sum();
    if future > 0 || !listing.skipped.is_empty() {
        Some(RestoreOutcome::ListingGap {
            skipped: listing.skipped.clone(),
            future,
        })
    } else {
        None
    }
}


/// True when a backed-up path is `path` itself or one of its ancestors, component by component.
pub fn covers(snapshot: &Snapshot, path: &str) -> bool {
    snapshot.paths.iter().any(|root| {
        let base = root.trim_end_matches('/');
        path == base || path.strip_prefix(base).is_some_and(|rest| rest.starts_with('/'))
    })
}


pub fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}


/// A non-zero exit, a timeout and an oversized output are outcomes; the bytes of a failed dump are never digested.
pub fn judge(dump: Result<Vec<u8>, RunFailure>, test: &RestoreTest) -> Result<RestoreOutcome, ResticError> {
    match dump {
        Ok(bytes) if digest_hex(&bytes) == test.sha256 => Ok(RestoreOutcome::Restored),
        Ok(_) => Ok(RestoreOutcome::DigestMismatch),
        Err(RunFailure::TooLarge) => Ok(RestoreOutcome::TooLarge),
        Err(RunFailure::TimedOut) => Ok(RestoreOutcome::Timeout),
        Err(RunFailure::Failed { code, .. }) => Ok(RestoreOutcome::Failed { code }),
        Err(other) => Err(ResticError::from(other)),
    }
}


/// The common prefix without `--json`, then `--no-cache --no-lock dump <snapshot id> <path>`.
pub fn dump_arguments<'a>(source: &'a ResticSource, transport: &'a [String], snapshot_id: &'a str, path: &'a str) -> Vec<&'a str> {
    transport
        .iter()
        .map(String::as_str)
        .chain(["-r", source.location.as_str(), "--password-file", source.password_file.as_str()])
        .chain(DUMP_FLAGS)
        .chain([snapshot_id, path])
        .collect()
}


/// Runs `cat config`, `snapshots` and one `dump` within `deadline` in total; the password file is checked again afterwards.
pub fn restore_test(
    program: &Path,
    tenant: &TenantScope,
    source: &ResticSource,
    test: &RestoreTest,
    limits: &Limits,
    deadline: Duration,
    clock: Clock,
) -> Result<RestoreResult, ResticError> {
    if valid_source(source) && valid_test(test) {
        let checked = open_secret(Path::new(&source.password_file)).map_err(password_failure)?;
        let transport = sftp_transport(&source.location);
        let start = Instant::now();
        let config = run_command(program, &command_arguments(source, &transport, &CONFIG_VERB), CONFIG_CAP_BYTES, deadline)?;
        let key = config_id(&config)?;
        let snapshots = run_command(
            program,
            &command_arguments(source, &transport, &SNAPSHOTS_VERB),
            limits.max_bytes,
            deadline.saturating_sub(start.elapsed()),
        )?;
        let listing = parse_restic(snapshots.as_slice(), &key, limits)?;
        let now = clock();
        let gap = listing_gap(&listing, &test.host, now);
        let chosen = choose(&listing.snapshots, &test.host, now).filter(|_| gap.is_none());
        let outcome = match (gap, chosen) {
            (Some(found), _) => found,
            (None, None) => RestoreOutcome::NoSnapshot,
            (None, Some(snapshot)) if !covers(snapshot, &test.path) => RestoreOutcome::NotCovered,
            (None, Some(snapshot)) => judge(
                run_command(
                    program,
                    &dump_arguments(source, &transport, &snapshot.id, &test.path),
                    test.max_bytes,
                    deadline.saturating_sub(start.elapsed()),
                ),
                test,
            )?,
        };
        unchanged(&checked, &source.password_file)?;
        Ok(RestoreResult {
            tenant: tenant.clone(),
            config_id: key,
            snapshot_id: chosen.map(|snapshot| snapshot.id.clone()),
            snapshot_time: chosen.map(|snapshot| snapshot.time),
            tested_at: clock(),
            outcome,
        })
    } else {
        Err(ResticError::Refused)
    }
}
