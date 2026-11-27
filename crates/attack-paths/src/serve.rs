//! The `ostyr-attack-paths` service: one stored report per tenant on a schedule, until the interrupt wait resolves; logs on stderr.


use crate::ad::{apply_ad_tags, graph_from_snapshot};
use crate::error::{StoreError, TagsError, TenantError};
use crate::input::{is_unchanged, open_stamped, run_mid_read, untouched};
use crate::model::{Graph, Limits, NodeKind, PathSet};
use crate::paths::paths_to_critical;
use crate::settings::{boxed_reload_audit, load_settings, open_attack_settings, pg_digest, AttackSettings, TenantEntry};
use crate::store::{store_report, StoreOutcome, MIGRATIONS, MIGRATION_NAMESPACE};
use crate::tags::load_tags_with;
use crate::types::{Executor, HangupFn, Hangups, InterruptFn, InterruptWait, MidRead, RoundResult, ServiceFuture, StopWatchFn, WaitFn};
use ad_posture::limits::Limits as SnapshotLimits;
use ad_posture::model::Snapshot;
use ad_posture::snapshot::read_snapshot;
use alerts::pg::pg_executor;
use core_audit::log::open_file_log;
use core_config::parse::read_file;
use core_config::reload::{current_config, ReloadEngine};
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::migrate::migrate;
use core_pg::settings::{parse_settings as parse_pg_settings, PgSettings};
use std::error::Error;
use std::fmt::Display;
use std::future::pending;
use std::io::{self, stderr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::spawn_blocking;
use tracing::{error, info, warn};


const USAGE: &str = "usage: ostyr-attack-paths <settings.yaml>";


const DEBOUNCE: Duration = Duration::from_millis(300);


const ROUNDS: u64 = 1_000_000_000;


pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);


/// Characters of an error text that reach a log line; the rest is cut.
pub const MAX_LOG_CHARS: usize = 256;


pub const CUT_MARKER: &str = "...[cut]";


pub const CLASS_OUTCOME_UNKNOWN: &str = "store_outcome_unknown";


pub const CLASS_FAILED: &str = "tenant_failed";


pub const CLASS_INPUT_CHANGED: &str = "input_changed";


pub const CLASS_INPUT_INCOMPLETE: &str = "input_incomplete";


/// What the graph build and the tag file left out of one tenant's report, as counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphGaps {
    pub nodes: usize,
    pub edges: usize,
    pub graph_truncated: bool,
    pub incomplete_nodes: usize,
    pub skipped_tags: usize,
}


/// A tenant's computed graph and result, before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Computed {
    pub graph: Graph,
    pub found: PathSet,
    pub gaps: GraphGaps,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantReport {
    pub outcome: StoreOutcome,
    pub paths: usize,
    pub gaps: GraphGaps,
}


/// The text of an error with control characters escaped and at most `MAX_LOG_CHARS` characters, so no file name or peer text forges a log line.
pub fn safe_text(error: &dyn Display) -> String {
    let text = error.to_string();
    let escaped: String = text.escape_debug().collect();
    let cut = escaped.chars().count() > MAX_LOG_CHARS;
    let shown: String = escaped.chars().take(MAX_LOG_CHARS).collect();
    if cut {
        format!("{shown}{CUT_MARKER}")
    } else {
        shown
    }
}


pub fn pause(duration: Duration) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
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


#[cfg(unix)]
pub fn listen_for_hangups() -> io::Result<Hangups> {
    signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub fn listen_for_hangups() -> io::Result<Hangups> {
    Ok(Hangups)
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


/// Starts reading the SIGHUP stream registered at the very start of `start`: a hangup that arrived before the engine existed is reloaded now.
#[cfg(unix)]
pub fn keep_hangups(mut stream: Hangups, engine: &Arc<ReloadEngine<AttackSettings>>) -> ReloadThread {
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
pub fn keep_hangups(_stream: Hangups, _engine: &Arc<ReloadEngine<AttackSettings>>) -> NoSignals {
    NoSignals
}


pub async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).with_ansi(false).finish())?;
    start(Path::new(settings_file), ROUNDS, listen_for_signals, listen_for_hangups, pause).await
}


/// The interrupt and the SIGHUP stream are armed before the first file is read; the migration and every round run to their end once begun.
pub async fn start(settings_file: &Path, rounds: u64, interrupt: InterruptFn, hangup: HangupFn, wait: WaitFn) -> Result<(), Box<dyn Error>> {
    let mut interrupted = interrupt()?;
    let hangups = hangup()?;
    let baseline = load_settings(settings_file)?;
    let pg_file = baseline.pg_settings.clone();
    let pg_text = read_file(&pg_file)?;
    let pg = parse_pg_settings(&pg_text, &pg_file.display().to_string())?;
    let audit_log = open_file_log(&baseline.audit_file)?;
    let engine = Arc::new(open_attack_settings(
        settings_file,
        baseline,
        pg_digest(&pg_text),
        boxed_reload_audit(audit_log),
    )?);
    let settings_watch = watch_files(Arc::clone(&engine), &[settings_file.to_path_buf(), pg_file], DEBOUNCE)?;
    let _reloads = keep_hangups(hangups, &engine);
    let stop_watch: StopWatchFn = Box::new(move || settings_watch.stop());
    serve_then_quiesce(stop_watch, rounds, &engine, &pg, wait, interrupt, &mut interrupted).await
}


/// Serves, then stops the file watch (its thread is joined) and takes the reload gate, so a reload in flight ends and is audited before the return.
pub async fn serve_then_quiesce(
    stop_watch: StopWatchFn,
    rounds: u64,
    engine: &ReloadEngine<AttackSettings>,
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
    engine: &ReloadEngine<AttackSettings>,
    pg: &PgSettings,
    wait: WaitFn,
    interrupt: InterruptFn,
    interrupted: &mut InterruptWait,
) -> Result<(), Box<dyn Error>> {
    let migration: ServiceFuture<'_> = Box::pin(async {
        migrate_store(pg).await?;
        Ok(())
    });
    let stopped = run_until_interrupt("migration", migration, interrupt, interrupted).await?;
    if stopped {
        Ok(())
    } else {
        let tenants = current_config(engine).tenants.len();
        info!(tenants, "serving");
        run_rounds(rounds, engine, pg, wait, interrupt, interrupted).await
    }
}


pub async fn migrate_store(pg: &PgSettings) -> Result<Vec<String>, PgError> {
    let client = connect(pg).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, Duration::from_secs(pg.statement_timeout_secs)).await
}


/// Runs the future on its own runtime, then gives a blocking task `grace` to finish before it is abandoned.
pub fn block_on_with_grace(future: ServiceFuture<'_>, grace: Duration) -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(future);
    runtime.shutdown_timeout(grace);
    result
}


/// How work in flight ended when raced against the first interrupt.
pub enum End {
    Finished(Result<(), Box<dyn Error>>),
    Interrupted(io::Result<()>),
}


/// After the first interrupt the work runs to its end; a later interrupt is logged and ignored, nothing cuts it.
pub async fn finish(what: &str, work: &mut ServiceFuture<'_>, interrupt: InterruptFn) -> Result<(), Box<dyn Error>> {
    let mut second = interrupt().unwrap_or_else(|failure| {
        warn!(%failure, "no second interrupt can be armed");
        Box::pin(pending())
    });
    info!(what, "interrupt received, finishing the work in flight");
    tokio::select! {
        biased;
        finished = &mut *work => finished,
        _ = &mut second => {
            warn!(what, "stop already in progress, the work in flight runs to its end");
            work.await
        }
    }
}


/// The work raced against the interrupt; the answer is whether the interrupt ended the service.
pub async fn run_until_interrupt(
    what: &str,
    mut work: ServiceFuture<'_>,
    interrupt: InterruptFn,
    interrupted: &mut InterruptWait,
) -> Result<bool, Box<dyn Error>> {
    let ended = tokio::select! {
        biased;
        result = &mut work => End::Finished(result),
        waited = &mut *interrupted => End::Interrupted(waited),
    };
    match ended {
        End::Finished(result) => result.map(|()| false),
        End::Interrupted(waited) => {
            let result = finish(what, &mut work, interrupt).await;
            result?;
            waited?;
            Ok(true)
        }
    }
}


/// A failed round is logged and the next one waits for the interval, so a broken database never makes a hot loop.
pub async fn run_rounds(
    rounds: u64,
    engine: &ReloadEngine<AttackSettings>,
    pg: &PgSettings,
    wait: WaitFn,
    interrupt: InterruptFn,
    interrupted: &mut InterruptWait,
) -> Result<(), Box<dyn Error>> {
    let mut stopped = false;
    let mut done = 0;
    while !stopped && done < rounds.min(ROUNDS) {
        let live = current_config(engine);
        let round: ServiceFuture<'_> = Box::pin(async {
            report(&one_round(pg, &live).await);
            Ok(())
        });
        stopped = run_until_interrupt("round", round, interrupt, interrupted).await?;
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


/// Reads the snapshot and the tag file through handles checked as regular files, builds the graph and searches it; the users and workstations are the entry points.
pub fn compute(entry: &TenantEntry, limits: Limits) -> Result<Computed, TenantError> {
    compute_with(entry, limits, untouched)
}


/// `compute` with a hook run after each file was read, so a test changes a file at that exact point.
pub fn compute_with(entry: &TenantEntry, limits: Limits, mid_read: MidRead) -> Result<Computed, TenantError> {
    let snapshot = read_snapshot_stable(&entry.snapshot_file, mid_read)?;
    snapshot.bounds.first().map_or(Ok(()), |hit| {
        Err(TenantError::SnapshotBound {
            bound: hit.bound,
            observed: hit.observed,
            limit: hit.limit,
        })
    })?;
    let mut built = graph_from_snapshot(&snapshot);
    built
        .graph
        .nodes
        .iter_mut()
        .for_each(|node| node.entry_point = matches!(node.kind, NodeKind::User | NodeKind::Workstation));
    let tags = load_tags_with(&entry.tags_file, mid_read)?;
    let skipped_tags = apply_ad_tags(&mut built, &tags)?.len();
    let mut found = paths_to_critical(&built.graph, limits)?;
    found.truncated |= built.truncated;
    let gaps = GraphGaps {
        nodes: built.graph.nodes.len(),
        edges: built.graph.edges.len(),
        graph_truncated: built.truncated,
        incomplete_nodes: built.incomplete.len(),
        skipped_tags,
    };
    Ok(Computed {
        graph: built.graph,
        found,
        gaps,
    })
}


/// The snapshot through a handle opened without following a symlink; it is refused when the handle changed while it was read.
pub fn read_snapshot_stable(path: &Path, mid_read: MidRead) -> Result<Snapshot, TenantError> {
    let name = path.display().to_string();
    let (handle, before) = open_stamped(path, &name)?;
    let read = read_snapshot(&handle, &SnapshotLimits::default());
    run_mid_read(mid_read, path, &name)?;
    is_unchanged(&handle, &before, &name)?.then_some(()).ok_or(TenantError::SnapshotChanged)?;
    Ok(read?)
}


/// One tenant: the blocking read and search on the blocking pool, then one stored report.
pub async fn tenant_round(exec: Executor<'_, '_>, entry: &TenantEntry, limits: Limits) -> Result<TenantReport, TenantError> {
    let owned = entry.clone();
    let computed = spawn_blocking(move || compute(&owned, limits)).await??;
    let outcome = store_report(exec, &entry.tenant, &computed.graph, &computed.found, OffsetDateTime::now_utc()).await?;
    Ok(TenantReport {
        outcome,
        paths: computed.found.paths.len(),
        gaps: computed.gaps,
    })
}


/// One connection, then every tenant in turn; a tenant that fails is recorded and the others still run.
pub async fn one_round(pg: &PgSettings, live: &AttackSettings) -> RoundResult {
    let client = connect(pg).await?;
    let exec = pg_executor(&client, Duration::from_secs(live.deadline_seconds));
    let limits = Limits {
        max_depth: live.max_depth,
        max_paths: live.max_paths,
    };
    let mut runs = Vec::new();
    for entry in &live.tenants {
        runs.push((entry.tenant.clone(), tenant_round(&exec, entry, limits).await));
    }
    Ok(runs)
}


/// A store call whose answer was lost or unreadable may have committed: only a server error or a timeout before the commit is a plain failure.
pub fn failure_class(failure: &TenantError) -> &'static str {
    match failure {
        TenantError::SnapshotChanged | TenantError::Tags(TagsError::Changed) => CLASS_INPUT_CHANGED,
        TenantError::Tags(TagsError::Incomplete) => CLASS_INPUT_INCOMPLETE,
        TenantError::Store(StoreError::Store(PgError::Server { .. } | PgError::StatementTimeout { .. } | PgError::ConnectTimeout { .. })) => {
            CLASS_FAILED
        }
        TenantError::Store(StoreError::Store(_) | StoreError::BadRow) => CLASS_OUTCOME_UNKNOWN,
        _ => CLASS_FAILED,
    }
}


/// A fixed category of a store failure for the log line; empty for a failure that never reached the store.
pub fn store_cause(failure: &TenantError) -> &'static str {
    match failure {
        TenantError::Store(StoreError::Store(PgError::ClientDeadline { .. })) => "client_deadline",
        TenantError::Store(StoreError::Store(PgError::StatementTimeout { .. })) => "statement_timeout",
        TenantError::Store(StoreError::Store(PgError::Server { .. })) => "server_error",
        TenantError::Store(StoreError::Store(PgError::ConnectTimeout { .. })) => "connect_timeout",
        TenantError::Store(StoreError::Store(_)) => "database",
        TenantError::Store(StoreError::BadRow) => "bad_answer",
        _ => "none",
    }
}


pub fn report(result: &RoundResult) {
    match result {
        Ok(runs) => runs.iter().for_each(|(tenant, run)| report_tenant(tenant, run)),
        Err(failure) => {
            let text = safe_text(failure);
            error!(failure = text.as_str(), "round failed before any tenant ran");
        }
    }
}


pub fn report_tenant(tenant: &str, run: &Result<TenantReport, TenantError>) {
    match run {
        Ok(done) => {
            let status = match done.outcome {
                StoreOutcome::Stored { id } => format!("stored id={id}"),
                StoreOutcome::AlreadyStored { id } => format!("unchanged id={id}"),
            };
            let (paths, gaps) = (done.paths, &done.gaps);
            let (nodes, edges) = (gaps.nodes, gaps.edges);
            info!(tenant, status = status.as_str(), paths, nodes, edges, "attack path report");
            report_gaps(tenant, gaps);
        }
        Err(failure) => {
            let text = safe_text(failure);
            let class = failure_class(failure);
            let cause = store_cause(failure);
            error!(tenant, class, cause, failure = text.as_str(), "attack path report failed");
        }
    }
}


/// One `warn!` when the graph was cut or incomplete, or a tag named an entry that was cut: the stored report is marked truncated too.
pub fn report_gaps(tenant: &str, gaps: &GraphGaps) {
    let (truncated, incomplete, skipped) = (gaps.graph_truncated, gaps.incomplete_nodes, gaps.skipped_tags);
    if truncated || incomplete > 0 || skipped > 0 {
        warn!(tenant, truncated, incomplete, skipped, "incomplete graph, report marked truncated");
    }
}
