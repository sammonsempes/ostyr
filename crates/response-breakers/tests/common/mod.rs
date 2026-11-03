pub mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::cli::proposed;
use response_breakers::error::BreakerError;
use response_breakers::model::{ActionKind, Verdict};
use response_breakers::store::sync_path;
use response_breakers::types::SyncFn;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;


pub const START: i64 = 1_800_000_000;


pub const HOUR: i64 = 3600;


pub const DAY: i64 = 86_400;


pub const TENANT: &str = "acme";


pub const BIG_FLEET: u64 = 1_000_000;


pub const DEFAULT_LIMITS: &str = "limits: {}\n";


pub struct Harness {
    pub dir: TempDir,
    pub breakers: Breakers,
    pub clock: Arc<AtomicI64>,
    pub entries: Arc<Mutex<Vec<NewEntry>>>,
    pub fail_audit: Arc<AtomicBool>,
}


pub fn limits_path(dir: &Path) -> PathBuf {
    dir.join("limits.yaml")
}


pub fn store_path(dir: &Path) -> PathBuf {
    dir.join("counters.json")
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub fn open_in(
    dir: &Path,
    clock: &Arc<AtomicI64>,
    entries: &Arc<Mutex<Vec<NewEntry>>>,
    fail_audit: &Arc<AtomicBool>,
    sync: SyncFn,
) -> Result<Breakers, BreakerError> {
    let log = genesis_log(io::sink());
    let sink = Arc::clone(entries);
    let failing = Arc::clone(fail_audit);
    let ticking = Arc::clone(clock);
    open_breakers(BreakerSettings {
        config_path: limits_path(dir),
        store_path: store_path(dir),
        sync,
        audit: Arc::new(move |entry: NewEntry| {
            sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
            if failing.load(Ordering::SeqCst) {
                Err(AuditError::LogPoisoned)
            } else {
                append(&log, entry)
            }
        }),
        clock: Box::new(move || OffsetDateTime::from_unix_timestamp(ticking.load(Ordering::SeqCst)).unwrap_or(OffsetDateTime::UNIX_EPOCH)),
    })
}


pub fn harness_with(limits: &str, sync: SyncFn) -> Result<Harness, Box<dyn Error>> {
    let dir = tempdir()?;
    replace_file(&limits_path(dir.path()), limits)?;
    let clock = Arc::new(AtomicI64::new(START));
    let entries = Arc::new(Mutex::new(Vec::new()));
    let fail_audit = Arc::new(AtomicBool::new(false));
    let breakers = open_in(dir.path(), &clock, &entries, &fail_audit, sync)?;
    Ok(Harness {
        dir,
        breakers,
        clock,
        entries,
        fail_audit,
    })
}


pub fn harness(limits: &str) -> Result<Harness, Box<dyn Error>> {
    harness_with(limits, sync_path)
}


pub fn reopen(harness: &Harness) -> Result<Breakers, BreakerError> {
    open_in(harness.dir.path(), &harness.clock, &harness.entries, &harness.fail_audit, sync_path)
}


pub fn advance(harness: &Harness, seconds: i64) {
    harness.clock.fetch_add(seconds, Ordering::SeqCst);
}


pub fn recorded(harness: &Harness) -> Result<Vec<NewEntry>, Box<dyn Error>> {
    Ok(harness.entries.lock().map_err(|_| "poisoned")?.clone())
}


pub fn verdict_for(breakers: &Breakers, tenant: &str, kind: ActionKind, tags: &[&str]) -> Verdict {
    response_breakers::check::check(breakers, &proposed(tenant, "target-1", tags, kind))
}
