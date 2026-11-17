use crate::cursor::{read_counter, set_aside, write_state_text};
use crate::error::{SensorError, SourceError};
use crate::model::{CommandSpec, Failure, Manager, SourceSettings, StateDir, SummaryFacts, UpdateEnv, UpdateSettings};
use crate::spool::{append_locked, append_within};
use crate::types::{Collected, SharedSource, SharedUpdates};
use agent_channel::types::{ClockFn, PauseFn};
use patch_inventory::apt::parse_apt;
use patch_inventory::dnf::parse_dnf;
use patch_inventory::error::InventoryError;
use patch_inventory::model::{Device, SkipReason, Update};
use patch_inventory::types::SkipCounts;
use serde_json::{json, Map, Value};
use std::fs;
use std::iter::once;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};


pub const APT_PATH: &str = "/usr/bin/apt";


pub const DNF_PATH: &str = "/usr/bin/dnf";


pub const ENV_LC_ALL: (&str, &str) = ("LC_ALL", "C");


pub const ENV_PATH: (&str, &str) = ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");


pub const APT_LISTS_DIR: &str = "/var/lib/apt/lists";


pub const COUNTER_SUFFIX: &str = ".updates-run";


pub const MAX_LISTS_ENTRIES: usize = 10_000;


pub const DATASET_UPDATE: &str = "ostyr.updates";


pub const DATASET_SUMMARY: &str = "ostyr.updates.summary";


pub const OUTCOME_OK: &str = "ok";


pub const OUTCOME_COUNTER_RESET: &str = "counter_reset";


pub const MAX_UPDATE_EVENTS_PER_RUN: usize = 5_000;


pub const OUTCOME_SPOOL_FULL: &str = "spool_full";


pub const SKIP_EVENT_TOO_LONG: &str = "event_too_long";


pub const DNF_CHECK_UPDATE_AVAILABLE: i32 = 100;


/// The only variables a package manager child sees.
pub fn child_environment() -> Vec<(String, String)> {
    [ENV_LC_ALL, ENV_PATH].map(|(name, value)| (name.to_owned(), value.to_owned())).to_vec()
}


pub fn command(program: &str, arguments: &[&str], accepted_codes: &[i32], max_output: u64) -> CommandSpec {
    CommandSpec {
        program: program.into(),
        arguments: arguments.iter().map(|argument| (*argument).to_owned()).collect(),
        environment: Some(child_environment()),
        accepted_codes: accepted_codes.to_vec(),
        max_output,
    }
}


pub fn failure_of_command(error: SensorError) -> Failure {
    match error {
        SensorError::Timeout => Failure::TimedOut,
        SensorError::TooLarge(_) => Failure::TooLarge,
        SensorError::Io(_) => Failure::Spawn,
        SensorError::Exit(code) => Failure::Exit(code),
        SensorError::Utf8(_) | SensorError::Parse => Failure::Exit(None),
    }
}


pub fn failure_of_inventory(error: &InventoryError) -> Failure {
    match error {
        InventoryError::Read(_) => Failure::Spawn,
        InventoryError::TooLarge { .. } | InventoryError::TooManyLines { .. } => Failure::TooLarge,
    }
}


pub fn outcome_name(failure: Failure) -> &'static str {
    match failure {
        Failure::TimedOut => "timed_out",
        Failure::TooLarge => "too_large",
        Failure::Exit(_) => "exit",
        Failure::Spawn => "spawn",
    }
}


pub fn skip_name(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::Malformed => "malformed",
        SkipReason::ControlCharacters => "control_characters",
        SkipReason::LineTooLong => "line_too_long",
        SkipReason::UnparsableVersion => "unparsable_version",
    }
}


pub fn device_of(env: &UpdateEnv) -> Device {
    Device {
        tenant: env.tenant.clone(),
        device_id: env.device_id.clone(),
    }
}


pub async fn run_one(env: &UpdateEnv, spec: CommandSpec, deadline: Duration) -> Result<Vec<u8>, Failure> {
    (env.run)(spec, deadline).await.map_err(failure_of_command)
}


/// `apt list --upgradable`: exit 0 only; the agent never refreshes the index.
pub async fn collect_apt(env: &UpdateEnv, deadline: Duration) -> Collected {
    let cap = env.limits.max_bytes as u64;
    let listing = run_one(env, command(APT_PATH, &["list", "--upgradable"], &[0], cap), deadline).await?;
    parse_apt(&device_of(env), listing.as_slice(), &env.limits).map_err(|error| failure_of_inventory(&error))
}


/// `dnf updateinfo list --updates` then `dnf check-update`, which exits 100 when updates exist and 0 when none (dnf(8)).
pub async fn collect_dnf(env: &UpdateEnv, deadline: Duration) -> Collected {
    let cap = env.limits.max_bytes as u64;
    let advisories = run_one(env, command(DNF_PATH, &["-q", "updateinfo", "list", "--updates"], &[0], cap), deadline).await?;
    let check = command(DNF_PATH, &["-q", "check-update"], &[0, DNF_CHECK_UPDATE_AVAILABLE], cap);
    let available = run_one(env, check, deadline).await?;
    parse_dnf(&device_of(env), advisories.as_slice(), available.as_slice(), &env.limits).map_err(|error| failure_of_inventory(&error))
}


/// Seconds since the newest regular file of the apt lists directory was written, read through one directory handle; `None` when it cannot be read.
pub fn lists_age(directory: &Path, now: u64) -> Option<u64> {
    let newest = fs::read_dir(directory)
        .inspect_err(|error| tracing::warn!(%error, "apt lists directory not readable"))
        .ok()?
        .take(MAX_LISTS_ENTRIES)
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(fs::Metadata::is_file)
        .filter_map(|metadata| metadata.modified().ok())
        .filter_map(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|written| written.as_secs())
        .max();
    newest.map(|written| now.saturating_sub(written))
}


/// Keeps the present values only, so an absent field is absent from the line.
pub fn present(fields: Vec<(&str, Option<Value>)>) -> Map<String, Value> {
    fields
        .into_iter()
        .filter_map(|(name, value)| value.map(|kept| (name.to_owned(), kept)))
        .collect()
}


pub fn event_line(run_id: u64, update: &Update) -> String {
    let package = present(vec![
        ("name", Some(json!(update.package))),
        ("architecture", Some(json!(update.architecture))),
        ("version", update.installed_version.as_ref().map(|version| json!(version))),
    ]);
    let details = present(vec![
        ("run_id", Some(json!(run_id))),
        ("candidate_version", Some(json!(update.candidate_version))),
        ("security", Some(json!(update.security))),
        ("origin", update.origin.as_ref().map(|origin| json!(origin))),
        ("advisory", update.advisory_id.as_ref().map(|advisory| json!(advisory))),
        ("severity", update.severity.as_ref().map(|severity| json!(severity))),
    ]);
    json!({
        "event": {"kind": "state", "category": ["package"], "type": ["info"], "dataset": DATASET_UPDATE},
        "package": package,
        "ostyr": {"update": details},
    })
    .to_string()
}


pub fn summary_line(facts: &SummaryFacts, skipped: &SkipCounts) -> String {
    let mut reasons: Map<String, Value> = skipped
        .iter()
        .map(|(reason, total)| (skip_name(*reason).to_owned(), json!(total)))
        .collect();
    if facts.oversized > 0 {
        reasons.insert(SKIP_EVENT_TOO_LONG.to_owned(), json!(facts.oversized));
    }
    let details = present(vec![
        ("run_id", Some(json!(facts.run_id))),
        ("count", Some(json!(facts.count))),
        ("outcome", Some(json!(facts.outcome))),
        ("exit_code", facts.exit_code.map(|code| json!(code))),
        ("truncated", (facts.truncated > 0).then(|| json!(facts.truncated))),
        ("skipped", Some(Value::Object(reasons))),
        ("lists_age_seconds", facts.lists_age_seconds.map(|age| json!(age))),
    ]);
    json!({
        "event": {"kind": "state", "category": ["package"], "type": ["info"], "dataset": DATASET_SUMMARY},
        "ostyr": {"update": details},
    })
    .to_string()
}


/// The next run id, persisted before any event is written; a counter that cannot be read, written or incremented refuses the run.
pub fn next_run_id(state: &StateDir, counter_file: &Path) -> Result<u64, SourceError> {
    let next = read_counter(state, counter_file)?
        .checked_add(1)
        .ok_or_else(|| SourceError::Counter(counter_file.to_path_buf()))?;
    write_state_text(state, counter_file, &format!("{next}\n"))?;
    Ok(next)
}


/// The run id of this run: a counter that is not a usable number is renamed aside through the held handle, logged once, and the ids restart at 1 (`true`).
pub fn claim_run_id(state: &StateDir, counter_file: &Path, now: u64) -> Result<(u64, bool), SourceError> {
    match next_run_id(state, counter_file) {
        Err(SourceError::Counter(_) | SourceError::NotRegular(_)) => {
            let aside = set_aside(state, counter_file, now)?;
            let aside_name = aside.display().to_string();
            tracing::warn!(aside = %aside_name, "run counter unusable, set aside, run ids restart at 1");
            write_state_text(state, counter_file, "1\n")?;
            Ok((1, true))
        }
        other => other.map(|run_id| (run_id, false)),
    }
}


/// The lines of one run, on a blocking thread: persist the run id, then append the events and the summary in one write. `false` when the run id could not be persisted and nothing was appended.
pub fn publish(env: &UpdateEnv, manager: Manager, source: &SourceSettings, collected: &Collected, now: u64) -> Result<bool, SourceError> {
    match claim_run_id(&env.state, &env.counter_file, now) {
        Ok((run_id, reset)) => append_run(env, manager, source, collected, (run_id, reset), now).map(|()| true),
        Err(error) => {
            tracing::warn!(%error, "update run id not persisted, the run is dropped");
            Ok(false)
        }
    }
}


/// At most `max_events` events and the summary in one write checked under the spool lock (`truncated` counts the omitted updates), or only a `spool_full` summary when they would push the spool over its bound; a reset run (`run_id`, `true`) appends the `counter_reset` summary alone.
pub fn append_run(
    env: &UpdateEnv,
    manager: Manager,
    source: &SourceSettings,
    collected: &Collected,
    (run_id, reset): (u64, bool),
    now: u64,
) -> Result<(), SourceError> {
    let age = (manager == Manager::Apt).then(|| lists_age(&env.lists_dir, now)).flatten();
    let (updates, skipped, outcome, exit_code) = match (collected, reset) {
        (_, true) => (&[][..], SkipCounts::new(), OUTCOME_COUNTER_RESET, None),
        (Ok(inventory), false) => (inventory.updates.as_slice(), inventory.skipped.clone(), OUTCOME_OK, None),
        (Err(failure), false) => (
            &[][..],
            SkipCounts::new(),
            outcome_name(*failure),
            match failure {
                Failure::Exit(code) => *code,
                _ => None,
            },
        ),
    };
    let scanned = updates.len().min(env.max_events);
    let kept: Vec<String> = updates
        .iter()
        .take(scanned)
        .map(|update| event_line(run_id, update))
        .filter(|line| line.len() <= env.line_limit)
        .collect();
    let facts = SummaryFacts {
        run_id,
        outcome,
        count: kept.len(),
        oversized: scanned - kept.len(),
        truncated: updates.len() - scanned,
        exit_code,
        lists_age_seconds: age,
    };
    let lines: Vec<String> = kept.into_iter().chain(once(summary_line(&facts, &skipped))).collect();
    let fitted = append_within(&env.lock, &env.spool, &env.sending, source.max_spool_bytes, &lines)?;
    if !fitted {
        let full = SummaryFacts {
            outcome: OUTCOME_SPOOL_FULL,
            count: 0,
            ..facts
        };
        append_locked(&env.lock, once(Ok(summary_line(&full, &skipped))), &env.spool)?;
    }
    Ok(())
}


/// One run with the snapshots it started with: the commands, then the blocking append; `false` when nothing was appended.
pub async fn run_once(env: &UpdateEnv, settings: &UpdateSettings, source: &SourceSettings, now: u64) -> Result<bool, SourceError> {
    let deadline = Duration::from_secs(settings.deadline_seconds);
    let collected = match settings.manager {
        Manager::Apt => Some(collect_apt(env, deadline).await),
        Manager::Dnf => Some(collect_dnf(env, deadline).await),
        Manager::None => None,
    };
    match collected {
        Some(found) => {
            if let Err(failure) = &found {
                tracing::warn!(outcome = outcome_name(*failure), "update inventory run failed");
            }
            let (owned, snapshot, manager) = (env.clone(), source.clone(), settings.manager);
            tokio::task::spawn_blocking(move || publish(&owned, manager, &snapshot, &found, now)).await?
        }
        None => Ok(false),
    }
}


/// Runs `max_runs` rounds, the first at start, each next one `interval_seconds` after the start of the previous; a failing spool write ends the agent, any other failed run is logged.
pub async fn run_updates(
    updates: &SharedUpdates,
    source: &SharedSource,
    env: &UpdateEnv,
    max_runs: u64,
    pause: &PauseFn,
    monotonic: &ClockFn,
    wall: &ClockFn,
) -> Result<u64, SourceError> {
    let mut published = 0;
    for _ in 0..max_runs {
        let (settings, source_settings) = (updates.load_full(), source.load_full());
        let started = monotonic();
        let done = run_once(env, &settings, &source_settings, wall())
            .await
            .inspect_err(|error| tracing::error!(%error, "update events not spooled, the agent stops"))?;
        published += u64::from(done);
        pause(Duration::from_secs(
            settings.interval_seconds.saturating_sub(monotonic().saturating_sub(started)),
        ))
        .await;
    }
    Ok(published)
}
