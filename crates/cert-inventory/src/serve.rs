//! The `ostyr-certs` service: the local certificate scan stored for one tenant on a schedule, until the interrupt wait resolves; logs on stderr.


use crate::error::{InventoryStoreError, RoundError};
use crate::model::{CertRecord, ScanOutcome, Source, SourceKind, StoreCounts, StoreLimits};
use crate::scan::{scan, ScanSettings, MAX_DEPTH_CEILING, MAX_ROOTS};
use crate::store::{store_records, DEFAULT_LIMITS, MIGRATIONS, MIGRATION_NAMESPACE, SOURCE_EXTRA_BYTES};
use crate::types::{InterruptFn, InterruptWait, ReloadSignals, ServiceFuture, StopWatchFn, WaitFn};
use alerts::pg::pg_executor;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::parse::read_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::{parse_settings as parse_pg_settings, PgSettings};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::{self, stderr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::spawn_blocking;
use tracing::{error, info, warn};


const USAGE: &str = "usage: ostyr-certs <settings.yaml>";


const DEBOUNCE: Duration = Duration::from_millis(300);


const ROUNDS: u64 = 1_000_000_000;


pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);


pub const MIN_INTERVAL_SECONDS: u64 = 3_600;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MAX_DEADLINE_SECONDS: u64 = 3_600;


pub const MAX_HOST_BYTES: usize = 253;


pub const MODULE: &str = "cert-inventory";


pub const SETTINGS_REQUEST: &str = "settings";


pub const UNKNOWN_CLASS: &str = "store_unknown";


/// Start-only: `tenant`, `pg_settings`, `audit_file` and `roots`. Live: the host label, the interval, the depth, the deadline and the certificate cap.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertSettings {
    pub tenant: String,
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
    pub roots: Vec<PathBuf>,
    pub host: String,
    pub interval_seconds: u64,
    pub max_depth: usize,
    pub deadline_seconds: u64,
    pub max_certs: usize,
}


/// Every gap of one scan: what it skipped, refused or never reached, as counts only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundGaps {
    pub max_files: usize,
    pub over_count: usize,
    pub not_regular: usize,
    pub too_large: usize,
    pub swapped: usize,
    pub vanished: usize,
    pub unreadable: usize,
    pub private_keys_refused: usize,
    pub roots_unreached: usize,
    pub roots_refused: usize,
    pub listing_cut: usize,
    pub paths_omitted: usize,
    pub malformed: Vec<(&'static str, usize)>,
}


/// What one round found and stored, in fixed-size data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundReport {
    pub records: usize,
    pub examined: usize,
    pub scan_errors: usize,
    pub counts: StoreCounts,
    pub gaps: RoundGaps,
}


pub fn setting_error(field: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: format!("settings.{field}"),
        reason: reason.to_owned(),
    }
}


pub fn within(field: &str, value: u64, low: u64, high: u64) -> Result<(), ConfigError> {
    if (low..=high).contains(&value) {
        Ok(())
    } else {
        Err(setting_error(field, &format!("must be between {low} and {high}")))
    }
}


pub const HOST_RULE: &str = "must be 1 to 253 letters, numbers, dots or hyphens, starting with a letter or a number";


pub fn require(holds: bool, field: &str, reason: &str) -> Result<(), ConfigError> {
    if holds {
        Ok(())
    } else {
        Err(setting_error(field, reason))
    }
}


pub fn is_host(host: &str) -> bool {
    (1..=MAX_HOST_BYTES).contains(&host.len())
        && host.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && host.bytes().next().is_some_and(|first| first.is_ascii_alphanumeric())
}


pub fn validate_settings(settings: &CertSettings) -> Result<(), ConfigError> {
    tenant_scope(&settings.tenant).map_err(|_refused| setting_error("tenant", "is not a valid tenant name"))?;
    within("roots", settings.roots.len() as u64, 1, MAX_ROOTS as u64)?;
    require(
        settings.roots.iter().all(|root| root.is_absolute()),
        "roots",
        "every root must be an absolute path",
    )?;
    require(settings.audit_file.is_absolute(), "audit_file", "must be an absolute path")?;
    require(is_host(&settings.host), "host", HOST_RULE)?;
    within("interval_seconds", settings.interval_seconds, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS)?;
    within("max_depth", settings.max_depth as u64, 1, MAX_DEPTH_CEILING as u64)?;
    within("deadline_seconds", settings.deadline_seconds, 1, MAX_DEADLINE_SECONDS)?;
    within("max_certs", settings.max_certs as u64, 1, DEFAULT_LIMITS.max_certs as u64)
}


pub fn load_settings(file: &Path) -> Result<CertSettings, ConfigError> {
    let settings: CertSettings = load_file(file)?;
    validate_settings(&settings)?;
    Ok(settings)
}


/// The first start-only field that differs from the start-up snapshot; the five live values may change.
pub fn start_only_field(baseline: &CertSettings, current: &CertSettings) -> Option<&'static str> {
    [
        (baseline.tenant != current.tenant).then_some("tenant"),
        (baseline.pg_settings != current.pg_settings).then_some("pg_settings"),
        (baseline.audit_file != current.audit_file).then_some("audit_file"),
        (baseline.roots != current.roots).then_some("roots"),
    ]
    .into_iter()
    .flatten()
    .next()
}


/// Everything except the five live values must equal the start-up snapshot.
pub fn start_only_changed(baseline: &CertSettings, current: &CertSettings) -> bool {
    start_only_field(baseline, current).is_some()
}


pub fn settings_state(settings: &CertSettings) -> ConfigState {
    [
        ("tenant", settings.tenant.clone()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("roots", format!("{:?}", settings.roots)),
        ("host", settings.host.clone()),
        ("interval_seconds", settings.interval_seconds.to_string()),
        ("max_depth", settings.max_depth.to_string()),
        ("deadline_seconds", settings.deadline_seconds.to_string()),
        ("max_certs", settings.max_certs.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn pg_digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}


/// The `pg_settings` file is read at start only: a later reload that finds other bytes in it is refused and audited `denied`.
pub fn settings_loader(file: PathBuf, baseline: CertSettings, pg_baseline: String) -> Box<LoaderFn<CertSettings>> {
    Box::new(move || {
        let current = load_settings(&file)?;
        let pg_now = pg_digest(&read_file(&baseline.pg_settings)?);
        let pg_field = (pg_now != pg_baseline).then_some("pg_settings (its file content)");
        match start_only_field(&baseline, &current).or(pg_field) {
            Some(field) => Err(setting_error(
                "start-only",
                &format!("{field} changed: it is read at start only, restart the service to change it"),
            )),
            None => Ok(current),
        }
    })
}


/// The audit identity of a reload: the tenant is the non-customer `all`, never the customer tenant the scan stores for.
pub fn reload_context(file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: "ostyr-certs".to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    }
}


/// The first read is the baseline; a later reload may change only the live values, any other change is refused and audited `denied`.
pub fn open_cert_settings_from(
    file: &Path,
    baseline: CertSettings,
    pg_baseline: String,
    audit: Box<SharedAuditFn>,
) -> Result<ReloadEngine<CertSettings>, ConfigError> {
    open_engine(
        settings_loader(file.to_path_buf(), baseline, pg_baseline),
        settings_state,
        Vec::new(),
        audit,
        reload_context(file),
    )
}


pub fn boxed_reload_audit(log: AuditLog<File>) -> Box<SharedAuditFn> {
    Box::new(move |entry| append_declared(&log, entry, &RELOAD_DECLARED_KEYS))
}


pub fn pause(duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


#[cfg(unix)]
pub fn listen_for_signals() -> io::Result<InterruptWait> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = terminate.recv() => Ok(()),
            _ = interrupt.recv() => Ok(()),
        }
    }))
}


#[cfg(not(unix))]
pub fn listen_for_signals() -> io::Result<InterruptWait> {
    Ok(Box::pin(tokio::signal::ctrl_c()))
}


/// The SIGHUP reload thread: dropping the guard closes the stream and joins the thread, so a reload in flight ends before the service returns.
#[cfg(unix)]
pub struct ReloadThread {
    pub handle: signal_hook::iterator::Handle,
    pub worker: Option<std::thread::JoinHandle<()>>,
}


#[cfg(unix)]
impl Drop for ReloadThread {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                error!("the reload thread panicked");
            }
        }
    }
}


/// Registers SIGHUP before any file is read, so a hangup during start is held until the reload thread takes it, never the default termination.
#[cfg(unix)]
pub fn arm_reload_signal() -> io::Result<ReloadSignals> {
    signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub fn arm_reload_signal() -> io::Result<ReloadSignals> {
    Ok(ReloadSignals)
}


#[cfg(unix)]
fn keep_signals(mut stream: ReloadSignals, engine: &Arc<ReloadEngine<CertSettings>>) -> ReloadThread {
    let handle = stream.handle();
    let shared = Arc::clone(engine);
    let worker = std::thread::spawn(move || {
        stream.forever().for_each(|received| {
            let outcome = core_config::reload::reload(&shared);
            tracing::debug!(received, ?outcome, "reload after signal");
        });
    });
    ReloadThread {
        handle,
        worker: Some(worker),
    }
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
fn keep_signals(_stream: ReloadSignals, _engine: &Arc<ReloadEngine<CertSettings>>) -> NoSignals {
    NoSignals
}


pub async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).with_ansi(false).finish())?;
    start(Path::new(settings_file), ROUNDS, listen_for_signals, pause).await
}


/// SIGHUP then the interrupt are armed before any file is read; the interrupt races the connect, the migration and the waits.
pub async fn start(settings_file: &Path, rounds: u64, interrupt: InterruptFn, wait: WaitFn) -> Result<(), Box<dyn Error>> {
    let reload_signals = arm_reload_signal()?;
    let mut interrupted = interrupt()?;
    let baseline = load_settings(settings_file)?;
    let pg_file = baseline.pg_settings.clone();
    let pg_text = read_file(&pg_file)?;
    let pg = parse_pg_settings(&pg_text, &pg_file.display().to_string())?;
    let audit_log = open_file_log(&baseline.audit_file)?;
    let engine = Arc::new(open_cert_settings_from(
        settings_file,
        baseline,
        pg_digest(&pg_text),
        boxed_reload_audit(audit_log),
    )?);
    let settings_watch = watch_files(Arc::clone(&engine), &[settings_file.to_path_buf(), pg_file], DEBOUNCE)?;
    let _settings_signals = keep_signals(reload_signals, &engine);
    let stop_watch: StopWatchFn = Box::new(move || settings_watch.stop());
    serve_then_quiesce(stop_watch, rounds, &engine, &pg, wait, interrupt, &mut interrupted).await
}


/// Serves, then stops the file watch (its thread is joined) and takes the reload gate, so a reload in flight ends and is audited before the return.
pub async fn serve_then_quiesce(
    stop_watch: StopWatchFn,
    rounds: u64,
    engine: &ReloadEngine<CertSettings>,
    pg: &PgSettings,
    wait: WaitFn,
    interrupt: InterruptFn,
    interrupted: &mut InterruptWait,
) -> Result<(), Box<dyn Error>> {
    let served = serve(rounds, engine, pg, wait, interrupt, interrupted).await;
    stop_watch();
    drop(engine.gate.lock().unwrap_or_else(PoisonError::into_inner));
    served
}


pub async fn serve(
    rounds: u64,
    engine: &ReloadEngine<CertSettings>,
    pg: &PgSettings,
    wait: WaitFn,
    interrupt: InterruptFn,
    interrupted: &mut InterruptWait,
) -> Result<(), Box<dyn Error>> {
    let first = current_config(engine);
    let migrated = tokio::select! {
        biased;
        waited = &mut *interrupted => Err(waited),
        done = migrate_store(pg) => Ok(done),
    };
    match migrated {
        Err(waited) => Ok(waited?),
        Ok(done) => {
            done?;
            let scope = tenant_scope(&first.tenant)?;
            info!(tenant = first.tenant, "serving");
            run_rounds(rounds, engine, pg, &scope, wait, interrupt, interrupted).await
        }
    }
}


/// Runs the future on its own runtime, then gives a blocking scan stuck on a dead mount `grace` to finish before it is abandoned.
pub fn block_on_with_grace(future: ServiceFuture<'_>, grace: Duration) -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(future);
    runtime.shutdown_timeout(grace);
    result
}


pub async fn migrate_store(pg: &PgSettings) -> Result<Vec<String>, PgError> {
    let client = connect(pg).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, Duration::from_secs(pg.statement_timeout_secs)).await
}


/// How a round in flight ended when raced against the first interrupt.
pub enum RoundEnd {
    Finished(Result<RoundReport, RoundError>),
    Interrupted(io::Result<()>),
}


/// After the first interrupt the round runs to its end and logs its line; a later interrupt is logged and ignored, nothing cuts the round.
pub async fn finish_round(round: &mut Pin<Box<impl Future<Output = Result<RoundReport, RoundError>>>>, interrupt: InterruptFn) {
    let mut second = interrupt().unwrap_or_else(|failure| {
        warn!(%failure, "no second interrupt can be armed");
        Box::pin(std::future::pending())
    });
    info!("interrupt received, finishing the round in flight");
    let result = tokio::select! {
        biased;
        finished = &mut *round => finished,
        _ = &mut second => {
            warn!("stop already in progress, the round in flight runs to its end");
            round.await
        }
    };
    report(&result);
}


/// One round raced against the interrupt; the answer is whether the interrupt ended the service.
pub async fn round_until_interrupt(
    pg: &PgSettings,
    scope: &TenantScope,
    live: &CertSettings,
    interrupt: InterruptFn,
    interrupted: &mut InterruptWait,
) -> Result<bool, Box<dyn Error>> {
    let mut round = Box::pin(one_round(pg, scope, live));
    let ended = tokio::select! {
        biased;
        result = &mut round => RoundEnd::Finished(result),
        waited = &mut *interrupted => RoundEnd::Interrupted(waited),
    };
    match ended {
        RoundEnd::Finished(result) => {
            report(&result);
            Ok(false)
        }
        RoundEnd::Interrupted(waited) => {
            finish_round(&mut round, interrupt).await;
            waited?;
            Ok(true)
        }
    }
}


/// A failed round is logged and the next one waits for the interval, so a broken database never makes a hot loop.
pub async fn run_rounds(
    rounds: u64,
    engine: &ReloadEngine<CertSettings>,
    pg: &PgSettings,
    scope: &TenantScope,
    wait: WaitFn,
    interrupt: InterruptFn,
    interrupted: &mut InterruptWait,
) -> Result<(), Box<dyn Error>> {
    let mut stopped = false;
    let mut done = 0;
    while !stopped && done < rounds.min(ROUNDS) {
        let live = current_config(engine);
        stopped = round_until_interrupt(pg, scope, &live, interrupt, interrupted).await?;
        done += 1;
        if !stopped {
            let next = current_config(engine);
            let waited = tokio::select! {
                biased;
                waited = &mut *interrupted => Some(waited),
                () = wait(Duration::from_secs(next.interval_seconds)) => None,
            };
            stopped = waited.transpose()?.is_some();
        }
    }
    Ok(())
}


pub fn gaps_of(outcome: &ScanOutcome, max_files: usize) -> RoundGaps {
    RoundGaps {
        max_files,
        over_count: outcome.skipped.over_count,
        not_regular: outcome.skipped.not_regular,
        too_large: outcome.skipped.too_large,
        swapped: outcome.skipped.swapped,
        vanished: outcome.skipped.vanished,
        unreadable: outcome.skipped.unreadable,
        private_keys_refused: outcome.private_keys_refused,
        roots_unreached: outcome.roots_unreached,
        roots_refused: outcome.roots_refused,
        listing_cut: outcome.listing_cut,
        paths_omitted: outcome.records.iter().map(|found| found.paths_omitted).sum(),
        malformed: outcome.malformed.iter().map(|(reason, count)| (*reason, *count)).collect(),
    }
}


/// The non-zero gap counts as `name=count` words, malformed files by fixed reason; empty when the scan lost nothing.
pub fn gap_text(gaps: &RoundGaps) -> String {
    let named = [
        ("over_count", gaps.over_count),
        ("not_regular", gaps.not_regular),
        ("too_large", gaps.too_large),
        ("swapped", gaps.swapped),
        ("vanished", gaps.vanished),
        ("unreadable", gaps.unreadable),
        ("private_keys_refused", gaps.private_keys_refused),
        ("roots_unreached", gaps.roots_unreached),
        ("roots_refused", gaps.roots_refused),
        ("listing_cut", gaps.listing_cut),
        ("paths_omitted", gaps.paths_omitted),
    ];
    named
        .iter()
        .map(|(name, count)| ((*name).to_owned(), *count))
        .chain(gaps.malformed.iter().map(|(reason, count)| (format!("malformed_{reason}"), *count)))
        .filter(|(_name, count)| *count > 0)
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<String>>()
        .join(" ")
}


pub fn report(result: &Result<RoundReport, RoundError>) {
    match result {
        Ok(round) => {
            let counts = round.counts;
            let (records, examined, scan_errors) = (round.records, round.examined, round.scan_errors);
            info!(?counts, records, examined, scan_errors, "scan round stored");
            report_gaps(&round.gaps);
        }
        Err(failure) => report_failure(failure),
    }
}


/// A client that stopped waiting, lost its connection, or got a reply that is not the store answer cannot say whether the statement committed.
pub fn outcome_unknown(error: &InventoryStoreError) -> bool {
    matches!(
        error,
        InventoryStoreError::Pg(PgError::ClientDeadline { .. } | PgError::Client(_)) | InventoryStoreError::BadRow { .. }
    )
}


/// A fixed class of a failed round: a store that stopped waiting may have committed, so it is `UNKNOWN_CLASS`, never "failed".
pub fn failure_class(failure: &RoundError) -> &'static str {
    match failure {
        RoundError::Scan(_) => "scan_task",
        RoundError::Pg(_) => "connect",
        RoundError::Store { source, .. } if outcome_unknown(source) => UNKNOWN_CLASS,
        RoundError::Store { .. } => "store",
    }
}


/// The index of the path whose store failed and the counts of the paths stored before it.
pub fn progress_of(failure: &RoundError) -> (usize, StoreCounts) {
    match failure {
        RoundError::Store { path_index, counts, .. } => (*path_index, *counts),
        RoundError::Scan(_) | RoundError::Pg(_) => (0, StoreCounts::default()),
    }
}


/// Logs the class and the partial counts only: a connect failure holds file names and is never printed.
pub fn report_failure(failure: &RoundError) {
    let class = failure_class(failure);
    let (path_index, counts) = progress_of(failure);
    if class == UNKNOWN_CLASS {
        error!(class, path_index, ?counts, "scan round outcome unknown, may have committed");
    } else {
        error!(class, path_index, ?counts, "scan round failed");
    }
}


/// One `warn!` of counts when anything was skipped, and a named budget overrun when `max_files` cut the scan short.
pub fn report_gaps(gaps: &RoundGaps) {
    let text = gap_text(gaps);
    if !text.is_empty() {
        warn!(gaps = text.as_str(), "scan gaps");
    }
    let budget = format!(
        "max_files={} over_count={} roots_unreached={} listing_cut={} paths_omitted={}",
        gaps.max_files, gaps.over_count, gaps.roots_unreached, gaps.listing_cut, gaps.paths_omitted
    );
    if gaps.over_count > 0 || gaps.listing_cut > 0 || gaps.paths_omitted > 0 {
        warn!(budget = budget.as_str(), "scan budget overrun");
    }
}


/// The percent-encoded form of a scan path: every byte outside the source allowlist (and `%` itself) becomes `%XX`.
pub fn encoded(path: &str) -> String {
    path.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || SOURCE_EXTRA_BYTES.contains(&byte) && byte != b'%' {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}


pub fn by_path(outcome: &ScanOutcome) -> BTreeMap<&str, Vec<CertRecord>> {
    let mut paths: BTreeMap<&str, Vec<CertRecord>> = BTreeMap::new();
    outcome
        .records
        .iter()
        .flat_map(|found| found.paths.iter().map(move |path| (path.as_str(), found.record.clone())))
        .for_each(|(path, record)| paths.entry(path).or_default().push(record));
    paths
}


pub fn sum_counts(left: StoreCounts, right: StoreCounts) -> StoreCounts {
    StoreCounts {
        inserted: left.inserted + right.inserted,
        seen_again: left.seen_again + right.seen_again,
        refused_full: left.refused_full + right.refused_full,
        refused_source: left.refused_source + right.refused_source,
        refused_record: left.refused_record + right.refused_record,
        duplicate_in_batch: left.duplicate_in_batch + right.duplicate_in_batch,
    }
}


/// One scan of the roots on the blocking pool, then one sighting per (certificate, path) stored for the tenant.
pub async fn one_round(pg: &PgSettings, scope: &TenantScope, live: &CertSettings) -> Result<RoundReport, RoundError> {
    let scan_settings = ScanSettings {
        roots: live.roots.clone(),
        max_depth: live.max_depth,
        ..ScanSettings::default()
    };
    let max_files = scan_settings.max_files;
    let outcome = spawn_blocking(move || scan(&scan_settings)).await?;
    outcome.errors.iter().for_each(|text| warn!(text = text.as_str(), "scan error"));
    let client = connect(pg).await?;
    let exec = pg_executor(&client, Duration::from_secs(live.deadline_seconds));
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let limits = StoreLimits {
        max_certs: live.max_certs,
        ..DEFAULT_LIMITS
    };
    let mut counts = StoreCounts::default();
    for (path_index, (path, records)) in by_path(&outcome).iter().enumerate() {
        let source = Source {
            kind: SourceKind::Scan,
            reference: format!("{}:{}", live.host, encoded(path)),
        };
        let stored = store_records(&exec, scope, &source, records, now, &limits).await;
        counts = sum_counts(
            counts,
            stored.map_err(|cause| RoundError::Store {
                path_index,
                counts,
                source: Box::new(cause),
            })?,
        );
    }
    Ok(RoundReport {
        records: outcome.records.len(),
        examined: outcome.examined,
        scan_errors: outcome.errors.len() + outcome.errors_omitted,
        counts,
        gaps: gaps_of(&outcome, max_files),
    })
}
