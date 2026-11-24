//! The `ostyr-oncall` service: alert source rounds until the interrupt wait resolves; logs on stderr, the purge audit in a core-audit file.

use crate::alert::Statement;
use crate::alert_source::{purge_statements, run_rounds, validate_source_settings, Round, RoundHooks, SourceSettings, PURGE_SQL};
use crate::backend::execute;
use crate::holder::{process_holder, validate_holder};
use crate::limits::PURGE_CLIENT_DEADLINE_MILLIS;
use crate::link::os_random;
use crate::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use crate::types::{AppendFn, InterruptWait, PurgedCounts};
use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use alerts::types::RowFuture;
use chrono::Utc;
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_audit::types::ParameterMap;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{bounded_value, current_config, open_engine, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_of, TenantScope};
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;
use tracing::{error, info, warn};


pub const USAGE: &str = "usage: ostyr-oncall <settings.yaml>";


pub const MODULE: &str = "oncall";


pub const PURGE_ACTION: &str = "oncall.outbox.purge";


pub const PURGE_TARGET: &str = "alert_outbox";


pub const PURGE_REQUEST: &str = "purge";


pub const SETTINGS_REQUEST: &str = "settings";


pub const PURGE_KEYS: [&str; 3] = ["rows", "tenants", "detail"];


pub const DEBOUNCE: Duration = Duration::from_millis(300);


pub const MAX_ROUNDS: usize = 100_000;


pub const ROUND_CAP_EXIT_CODE: u8 = 75;


pub const FAILURE_EXIT_CODE: u8 = 1;


pub const MILLIS_PER_SECOND: u64 = 1_000;


/// `pg_settings`, `label` and `audit_file` are read at start only (absolute paths); `source` is live.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub pg_settings: PathBuf,
    pub label: String,
    pub audit_file: PathBuf,
    pub source: SourceSettings,
}


/// The client deadline of the purge transaction and the one of the rollback that follows a purge deadline (a hung peer never blocks the round).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeDeadlines {
    pub purge: Duration,
    pub rollback: Duration,
}


/// How `start` ended: the interrupt, or the round cap (the supervisor restarts the process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    Interrupted,
    RoundCap,
}


pub fn setting_error(field: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: format!("settings.{field}"),
        reason: reason.to_owned(),
    }
}


pub fn validate_service(settings: &ServiceSettings, now: chrono::DateTime<Utc>) -> Result<(), ConfigError> {
    validate_holder(&settings.label).map_err(|_refused| setting_error("label", "must be 1 to 64 letters, digits, -, _ or ."))?;
    if !settings.audit_file.is_absolute() {
        Err(setting_error("audit_file", "must be an absolute path"))
    } else if !settings.pg_settings.is_absolute() {
        Err(setting_error("pg_settings", "must be an absolute path"))
    } else {
        validate_source_settings(&settings.source, now).map_err(|refused| setting_error("source", &refused.to_string()))
    }
}


pub fn load_service(file: &Path) -> Result<ServiceSettings, ConfigError> {
    let settings: ServiceSettings = load_file(file)?;
    validate_service(&settings, Utc::now())?;
    Ok(settings)
}


pub fn service_state(settings: &ServiceSettings) -> ConfigState {
    [
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("label", settings.label.clone()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("tenants", format!("{:?}", settings.source.tenants)),
        ("max_per_poll", settings.source.max_per_poll.to_string()),
        ("interval_seconds", settings.source.interval_seconds.to_string()),
        ("severity_map", format!("{:?}", settings.source.severity_map)),
        ("added_at", format!("{:?}", settings.source.added_at)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// Everything except `source` must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    let same_source = ServiceSettings {
        source: baseline.source.clone(),
        ..current.clone()
    };
    same_source != *baseline
}


pub fn service_loader(file: PathBuf, baseline: ServiceSettings) -> Box<LoaderFn<ServiceSettings>> {
    Box::new(move || {
        let current = load_service(&file)?;
        if start_only_changed(&baseline, &current) {
            Err(setting_error(
                "start-only",
                "pg_settings, label and audit_file are read at start only, restart the service to change them",
            ))
        } else {
            Ok(current)
        }
    })
}


/// The first read is the baseline; a later reload may change only `source`, any other change is refused and audited `denied`.
pub fn open_service_settings(file: &Path, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<ServiceSettings>, ConfigError> {
    let baseline = load_service(file)?;
    let tenant = carrier_tenant(&baseline.source);
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant,
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    };
    open_engine(service_loader(file.to_path_buf(), baseline), service_state, Vec::new(), audit, context)
}


/// The first configured tenant (the load checks that there is one), the tenant of the service's own audit records.
pub fn carrier_tenant(source: &SourceSettings) -> String {
    source.tenants.iter().take(1).cloned().collect::<Vec<String>>().join("")
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


pub fn purge_entry(tenant: &str, counts: &PurgedCounts) -> NewEntry {
    let rows: usize = counts.values().sum();
    let detail: Vec<String> = counts.iter().map(|(name, dropped)| format!("{name}={dropped}")).collect();
    let parameters: ParameterMap = [
        ("rows", rows.to_string()),
        ("tenants", counts.len().to_string()),
        ("detail", bounded_value(&detail.join(","))),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: MODULE.to_owned(),
        },
        tenant: tenant.to_owned(),
        module: MODULE.to_owned(),
        action: PURGE_ACTION.to_owned(),
        target: PURGE_TARGET.to_owned(),
        outcome: Outcome::Success,
        request_id: PURGE_REQUEST.to_owned(),
        justification: None,
        parameters,
    }
}


/// A failing append is named in the log and never stops the rounds.
pub fn audit_purge(append: AppendFn<'_>, tenant: &str, counts: &PurgedCounts) {
    if let Err(failure) = append(purge_entry(tenant, counts)) {
        error!(%failure, "the outbox purge audit could not be written");
    }
}


pub fn append_to(log: &AuditLog<File>, entry: NewEntry) -> Result<(), AuditError> {
    append_declared(log, entry, &PURGE_KEYS).map(|_record| ())
}


pub fn round_summary(round: &Round) -> String {
    let purged = round
        .purged
        .as_ref()
        .map_or_else(|failure| failure.to_string(), |counts| format!("{counts:?}"));
    let tenants: Vec<String> = round
        .outcomes
        .iter()
        .map(|(tenant, outcome)| {
            let text = outcome.as_ref().map_or_else(
                |failure| failure.to_string(),
                |counts| {
                    format!(
                        "opened:{} already:{} conflict:{} skipped_backlog:{}",
                        counts.opened, counts.already, counts.conflict, counts.skipped_backlog
                    )
                },
            );
            format!("{tenant}={text}")
        })
        .collect();
    let leased = round.leased.as_ref().map_or_else(|failure| failure.to_string(), ToString::to_string);
    format!("leased={leased} purged={purged} {}", tenants.join(" "))
}


pub fn report(round: &Round) {
    let line = round_summary(round);
    info!("round: {line}");
}


pub fn pause(duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


/// The purge runs as one transaction (`purge_statements`) under a client deadline above the server's own; a deadline rolls it back.
pub async fn purge_rows(client: &Client, deadlines: PurgeDeadlines, scope: TenantScope, params: Vec<String>) -> Result<Vec<Vec<String>>, PgError> {
    let tenant = tenant_of(&scope).to_owned();
    let bound: Vec<&(dyn ToSql + Sync)> = std::iter::once(&tenant as &(dyn ToSql + Sync))
        .chain(params.iter().map(|param| param as &(dyn ToSql + Sync)))
        .collect();
    let (set_timeout, set_idle, purge) = purge_statements();
    let work = async {
        client.batch_execute(&format!("BEGIN; {set_timeout}; {set_idle}")).await.map_err(reduce)?;
        let outcome = client.query(&purge, &bound).await.map_err(reduce);
        let end = if outcome.is_ok() { "COMMIT" } else { "ROLLBACK" };
        client.batch_execute(end).await.map_err(reduce)?;
        outcome
    };
    let finished = tokio::time::timeout(deadlines.purge, work).await;
    if finished.is_err() {
        match tokio::time::timeout(deadlines.rollback, client.batch_execute("ROLLBACK")).await {
            Ok(Ok(())) => {}
            Ok(Err(failure)) => warn!("rollback after a purge deadline failed: {failure}"),
            Err(_elapsed) => warn!("rollback after a purge deadline timed out"),
        }
    }
    let rows = finished.map_err(|_elapsed| PgError::StatementTimeout {
        seconds: deadlines.purge.as_secs(),
    })??;
    rows.iter()
        .map(|row| (0..row.len()).map(|index| row.try_get::<_, String>(index).map_err(reduce)).collect())
        .collect()
}


pub fn alerts_executor<'a>(
    client: &'a Client,
    deadline: Duration,
    purge_deadlines: PurgeDeadlines,
) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    let plain = pg_executor(client, deadline);
    move |scope, sql, params| -> RowFuture<'a> {
        if sql == PURGE_SQL {
            Box::pin(purge_rows(client, purge_deadlines, scope, params))
        } else {
            plain(scope, sql, params)
        }
    }
}


/// A closed session (idle-in-transaction timeout, server restart) is replaced once per round; a failed attempt is retried next round.
pub async fn refresh(client: &mut Client, pg: &PgSettings) {
    if client.is_closed() {
        match connect(pg).await {
            Ok(fresh) => *client = fresh,
            Err(failure) => warn!("reconnect failed, retrying next round: {failure}"),
        }
    }
}


/// Each round re-reads the live snapshot; the wait between rounds is the interval, so a dead database never gives a busy loop.
pub async fn poll_rounds(
    client: &mut Client,
    pg: &PgSettings,
    engine: &ReloadEngine<ServiceSettings>,
    holder: &str,
    rounds: usize,
    audit: &dyn Fn(&PurgedCounts),
) -> Finish {
    let deadline = Duration::from_secs(pg.statement_timeout_secs);
    let purge_deadline = Duration::from_millis(PURGE_CLIENT_DEADLINE_MILLIS);
    let purge_deadlines = PurgeDeadlines {
        purge: purge_deadline,
        rollback: purge_deadline,
    };
    let hooks = RoundHooks {
        now: Utc::now,
        wait: pause,
        report,
        audit_purge: audit,
    };
    for _round in 0..rounds {
        refresh(client, pg).await;
        let alerts_exec = alerts_executor(client, deadline, purge_deadlines);
        let mut exec = |scope: &TenantScope, statement: Statement| execute(client, deadline, scope.clone(), statement);
        let live = || current_config(engine).source.clone();
        run_rounds(1, &alerts_exec, &mut exec, holder, &hooks, &live).await;
    }
    warn!("the round cap was reached, exiting so the supervisor restarts the poller");
    Finish::RoundCap
}


#[cfg(unix)]
fn keep_signals<Config: Send + Sync + 'static>(engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(Arc::clone(engine), &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
fn keep_signals<Config>(_engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<NoSignals> {
    Ok(NoSignals)
}


/// SIGINT and SIGTERM, both registered before this returns, so a signal sent once the service logs `serving` is never lost.
#[cfg(unix)]
pub fn interrupt_wait() -> InterruptWait {
    use tokio::signal::unix::{signal, SignalKind};
    let registered = signal(SignalKind::interrupt()).and_then(|interrupt| signal(SignalKind::terminate()).map(|terminate| (interrupt, terminate)));
    wait_for_signals(registered)
}


/// A registration that failed is the error of the wait itself.
#[cfg(unix)]
pub fn wait_for_signals(registered: std::io::Result<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>) -> InterruptWait {
    Box::pin(async move {
        let (mut interrupt, mut terminate) = registered?;
        tokio::select! {
            _ = interrupt.recv() => Ok(()),
            _ = terminate.recv() => Ok(()),
        }
    })
}


#[cfg(not(unix))]
pub fn interrupt_wait() -> InterruptWait {
    Box::pin(tokio::signal::ctrl_c())
}


pub async fn run_service(arguments: &[String], interrupt: InterruptWait) -> Result<Finish, Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::stderr).finish())?;
    start(Path::new(settings_file), MAX_ROUNDS, interrupt).await
}


pub async fn start(settings_file: &Path, rounds: usize, interrupt: InterruptWait) -> Result<Finish, Box<dyn Error>> {
    let log = Arc::new(open_file_log(&load_service(settings_file)?.audit_file)?);
    let engine = Arc::new(open_service_settings(settings_file, boxed_reload_audit(&log))?);
    let _watch = watch_files(Arc::clone(&engine), &[settings_file.to_path_buf()], DEBOUNCE)?;
    let _signals = keep_signals(&engine)?;
    let begin = current_config(&engine);
    let pg = load_pg_settings(&begin.pg_settings)?;
    let mut client = connect(&pg).await?;
    let deadline = Duration::from_secs(pg.statement_timeout_secs);
    migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, deadline).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, deadline).await?;
    let holder = process_holder(Some(&begin.label), "", std::process::id(), os_random)?;
    let tenant = carrier_tenant(&begin.source);
    let audit = |counts: &PurgedCounts| audit_purge(&|entry| append_to(&log, entry), &tenant, counts);
    info!(holder, "serving");
    tokio::select! {
        biased;
        waited = interrupt => {
            waited?;
            Ok(Finish::Interrupted)
        },
        finish = poll_rounds(&mut client, &pg, &engine, &holder, rounds, &audit) => Ok(finish),
    }
}


/// The exit code of a finished run: 0 after an interrupt, `ROUND_CAP_EXIT_CODE` at the round cap, `FAILURE_EXIT_CODE` and one line on `out` for an error.
pub fn finish_code<Output: Write>(result: Result<Finish, Box<dyn Error>>, out: &mut Output) -> std::io::Result<u8> {
    match result {
        Ok(Finish::Interrupted) => Ok(0),
        Ok(Finish::RoundCap) => Ok(ROUND_CAP_EXIT_CODE),
        Err(failure) => writeln!(out, "{failure}").map(|()| FAILURE_EXIT_CODE),
    }
}
