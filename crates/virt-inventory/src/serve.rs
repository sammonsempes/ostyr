//! The `ostyr-virt-inventory` service: one fetch and CMDB sync per interval until the interrupt; logs on stderr.

use crate::error::{RoundError, ServiceError};
use crate::hangup::{arm_hangup, follow_hangup};
use crate::model::{Context, Live, RoundReport};
use crate::service::{load_live, open_live_engine, production_round, round_entry, ROUND_KEYS};
use crate::types::{InterruptFn, InterruptWait, RoundFn, WaitFn, WaitFuture};
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::migrate::migrate;
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use std::error::Error;
use std::fs::File;
use std::io::stderr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};


pub const MAX_ROUNDS: usize = u32::MAX as usize;


pub const DEBOUNCE: Duration = Duration::from_millis(300);


pub fn pause(duration: Duration) -> WaitFuture {
    Box::pin(tokio::time::sleep(duration))
}


/// Completes on `SIGTERM` or `SIGINT`; both handlers are installed when this returns, and a signal that arrives during a round is kept for the wait after it.
#[cfg(unix)]
pub fn stop_signals() -> std::io::Result<InterruptWait> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = terminate.recv() => (),
            _ = interrupt.recv() => (),
        }
        Ok(())
    }))
}


#[cfg(not(unix))]
pub fn stop_signals() -> std::io::Result<InterruptWait> {
    Ok(Box::pin(tokio::signal::ctrl_c()))
}


pub fn install_logging() -> Result<(), Box<dyn Error>> {
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).with_ansi(false).finish())?;
    Ok(())
}


pub fn exit_code(result: &Result<(), Box<dyn Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}


/// The failure carries its fixed text, the success its counts; nothing from the answer is logged raw.
pub fn log_round(result: &Result<RoundReport, RoundError>) {
    match result {
        Ok(round) => {
            let report = &round.sync;
            let created = report.created;
            let updated = report.updated;
            let conflicts = report.conflicts;
            let unapplied = report.unapplied;
            let refused = report.counters.refused + report.refused_by_cmdb;
            let skipped = round.skipped.unparsable + round.skipped.bad_field + round.skipped.duplicate + round.skipped.key_lost;
            info!(created, updated, conflicts, unapplied, refused, skipped, "virt round done");
        }
        Err(failure) => {
            let reason = failure.to_string();
            warn!(reason, "virt round failed, the last sync stands");
        }
    }
}


/// Holds the reload gate once: any reload in flight on the watcher or the signal thread has stored, published and audited before this returns.
pub fn drain(engine: &ReloadEngine<Live>) {
    if engine.gate.lock().is_err() {
        warn!("the reload gate was poisoned by a reload that panicked");
    }
}


/// Dropped last of the reload parts, after the signal thread and the file watcher have stopped, so `drain` sees the final reload.
pub struct Drain(pub Arc<ReloadEngine<Live>>);


impl Drop for Drain {
    fn drop(&mut self) {
        drain(&self.0);
    }
}


/// Whether the interrupt is already there; a signal that arrived earlier is kept by the stream.
pub async fn stop_pending(interrupted: &mut InterruptWait) -> std::io::Result<bool> {
    tokio::select! {
        biased;
        waited = &mut *interrupted => waited.map(|()| true),
        () = std::future::ready(()) => Ok(false),
    }
}


/// At most `max_rounds` rounds over one snapshot each; an interrupt is seen after the round, which finishes and is audited first.
pub async fn serve(
    engine: &ReloadEngine<Live>,
    audit: &AuditLog<File>,
    pg: &PgSettings,
    round: RoundFn,
    wait: WaitFn,
    max_rounds: usize,
    interrupted: &mut InterruptWait,
) -> Result<usize, Box<dyn Error>> {
    let mut done = 0;
    let mut stopped = false;
    while !stopped && done < max_rounds.min(MAX_ROUNDS) {
        stopped = stop_pending(interrupted).await?;
        if !stopped {
            let live = current_config(engine);
            let context = Context {
                fetch: live.fetch.clone(),
                pg: pg.clone(),
                limits: live.limits,
            };
            let result = round(&context).await;
            log_round(&result);
            append_declared(audit, round_entry(&live.fetch.cluster, &result), &ROUND_KEYS)?;
            done += 1;
            if done < max_rounds.min(MAX_ROUNDS) {
                let interval = Duration::from_secs(current_config(engine).service.interval_seconds);
                stopped = tokio::select! {
                    biased;
                    waited = &mut *interrupted => {
                        waited?;
                        true
                    }
                    () = wait(interval) => false,
                };
            }
        }
    }
    Ok(done)
}


pub async fn migrate_store(pg: &PgSettings) -> Result<Vec<String>, PgError> {
    let client = connect(pg).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, Duration::from_secs(pg.statement_timeout_secs)).await
}


/// The interrupt races the connect and the migration: a stop during start skips the first round and ends with status 0.
pub async fn run_service(
    engine: &ReloadEngine<Live>,
    audit: &AuditLog<File>,
    pg: &PgSettings,
    round: RoundFn,
    wait: WaitFn,
    max_rounds: usize,
    interrupted: &mut InterruptWait,
) -> Result<(), Box<dyn Error>> {
    let migrated = tokio::select! {
        biased;
        waited = &mut *interrupted => Err(waited),
        done = migrate_store(pg) => Ok(done),
    };
    match migrated {
        Err(waited) => Ok(waited?),
        Ok(done) => {
            done?;
            let live = current_config(engine);
            let tenant = live.fetch.tenant.clone();
            let cluster = live.fetch.cluster.clone();
            info!(tenant, cluster, "serving");
            serve(engine, audit, pg, round, wait, max_rounds, interrupted).await?;
            Ok(())
        }
    }
}


/// The three signals are armed before anything is read; one read of the service file serves the audit path and the baseline; both settings files are watched and reload on `SIGHUP`.
pub async fn start(settings_file: &Path, round: RoundFn, wait: WaitFn, max_rounds: usize, interrupt: InterruptFn) -> Result<(), Box<dyn Error>> {
    let mut interrupted = interrupt()?;
    let hangup = arm_hangup()?;
    let baseline = load_live(settings_file)?;
    let audit = Arc::new(open_file_log(&baseline.service.audit_file)?);
    let pg = load_pg_settings(&baseline.service.pg_settings)?;
    let watched = [settings_file.to_path_buf(), baseline.service.fetch_settings.clone()];
    let sink = Arc::clone(&audit);
    let audit_sink: Box<SharedAuditFn> = Box::new(move |entry| append_declared(&sink, entry, &RELOAD_DECLARED_KEYS));
    let opened = open_live_engine(settings_file, baseline, audit_sink)?;
    let engine = Arc::new(opened);
    let _drain = Drain(Arc::clone(&engine));
    let _watch = watch_files(Arc::clone(&engine), &watched, DEBOUNCE)?;
    let _hangup = follow_hangup(hangup, Arc::clone(&engine));
    run_service(&engine, &audit, &pg, round, wait, max_rounds, &mut interrupted).await
}


/// The argument check, the logging, then the service.
pub async fn run(arguments: &[String], interrupt: InterruptFn) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(ServiceError::Usage),
    }?;
    install_logging()?;
    start(Path::new(settings_file), production_round, pause, MAX_ROUNDS, interrupt).await
}
