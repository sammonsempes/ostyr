//! The `ostyr-virt-inventory` service: one fetch and CMDB sync per interval until the interrupt; logs on stderr.

use crate::cmdb_sync::SyncReport;
use crate::error::{RoundError, ServiceError};
use crate::model::Context;
use crate::service::{limits_of, load_service_settings, production_round, round_entry, ROUND_KEYS};
use crate::settings::load_settings;
use crate::types::{InterruptWait, RoundFn, WaitFn, WaitFuture};
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_audit::log::{append_declared, open_file_log};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::settings::load_settings as load_pg_settings;
use std::error::Error;
use std::io::stderr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tracing::{info, warn};


pub const MAX_ROUNDS: usize = u32::MAX as usize;


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
pub fn log_round(result: &Result<SyncReport, RoundError>) {
    match result {
        Ok(report) => {
            let created = report.created;
            let updated = report.updated;
            let conflicts = report.conflicts;
            let unapplied = report.unapplied;
            let refused = report.counters.refused + report.refused_by_cmdb;
            info!(created, updated, conflicts, unapplied, refused, "virt round done");
        }
        Err(failure) => {
            let reason = failure.to_string();
            warn!(reason, "virt round failed, the last sync stands");
        }
    }
}


/// At most `max_rounds` rounds, one after the other. An interrupt during a round is kept and seen at the wait after it, so the round finishes and its audit record is written before this returns; a failed round waits the whole interval like a good one.
pub async fn serve(
    context: &Context,
    round: RoundFn,
    wait: WaitFn,
    interval: Duration,
    max_rounds: usize,
    interrupt: &mut InterruptWait,
) -> Result<usize, Box<dyn Error>> {
    let mut done = 0;
    let mut stopped = false;
    while !stopped && done < max_rounds.min(MAX_ROUNDS) {
        let result = round(context).await;
        log_round(&result);
        append_declared(&context.audit, round_entry(&context.fetch.cluster, &result), &ROUND_KEYS)?;
        done += 1;
        if done < max_rounds.min(MAX_ROUNDS) {
            stopped = tokio::select! {
                biased;
                waited = &mut *interrupt => {
                    waited?;
                    true
                }
                () = wait(interval) => false,
            };
        }
    }
    Ok(done)
}


/// One read of the settings file serves the audit path and the baseline; the fetch file is checked, the audit log opened and the schema migrated before the first round.
pub async fn start(
    settings_file: &Path,
    round: RoundFn,
    wait: WaitFn,
    max_rounds: usize,
    mut interrupt: InterruptWait,
) -> Result<(), Box<dyn Error>> {
    let settings = load_service_settings(settings_file)?;
    let audit = open_file_log(&settings.audit_file)?;
    let fetch = load_settings(&settings.fetch_settings)?;
    let pg = load_pg_settings(&settings.pg_settings)?;
    let limits = limits_of(&settings)?;
    migrate(
        &connect(&pg).await?,
        MIGRATION_NAMESPACE,
        &MIGRATIONS,
        Duration::from_secs(pg.statement_timeout_secs),
    )
    .await?;
    let tenant = fetch.tenant.clone();
    let cluster = fetch.cluster.clone();
    let context = Context { fetch, pg, limits, audit };
    info!(tenant, cluster, "serving");
    serve(
        &context,
        round,
        wait,
        Duration::from_secs(settings.interval_seconds),
        max_rounds,
        &mut interrupt,
    )
    .await?;
    Ok(())
}


/// The argument check, the logging, then the service.
pub async fn run(arguments: &[String], interrupt: InterruptWait) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(ServiceError::Usage),
    }?;
    install_logging()?;
    start(Path::new(settings_file), production_round, pause, MAX_ROUNDS, interrupt).await
}
