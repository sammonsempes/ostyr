//! The `ostyr-siem-ingest` service: JetStream into ClickHouse until SIGINT or SIGTERM, settings reloaded on file change and SIGHUP.
use crate::batcher::{new_batcher, real_sleep, system_clock};
use crate::clickhouse::clickhouse_sink;
use crate::error::ServeError;
use crate::logging::build_subscriber;
use crate::model::Ended;
use crate::nats::nats_wiring;
use crate::pipeline::{new_pipeline, run_loop_capped, MAX_LOOP_CYCLES};
use crate::settings::{load_settings, open_settings_from, IngestSettings};
use crate::types::StopFn;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::RELOAD_DECLARED_KEYS;
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use std::fs::File;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};


pub const RUST_LOG: &str = "RUST_LOG";


pub const EXIT_FAILURE: u8 = 1;


pub const EXIT_CYCLE_CAP: u8 = 75;


const DEBOUNCE: Duration = Duration::from_millis(300);


/// Success only for an interrupt; the cycle cap and every start error are non-zero, so the supervisor restarts the service.
pub fn exit_code(result: &Result<Ended, ServeError>) -> u8 {
    match result {
        Ok(Ended::Stopped(_)) => 0,
        Ok(Ended::CycleCap(_)) => EXIT_CYCLE_CAP,
        Err(_) => EXIT_FAILURE,
    }
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


#[cfg(unix)]
pub fn keep_signals<Config: Send + Sync + 'static>(engine: &Arc<core_config::reload::ReloadEngine<Config>>) -> Result<impl Sized, ServeError> {
    core_config::signal::reload_on_signals(Arc::clone(engine), &[signal_hook::consts::SIGHUP]).map_err(ServeError::Signals)
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
pub fn keep_signals<Config>(_engine: &Arc<core_config::reload::ReloadEngine<Config>>) -> Result<NoSignals, ServeError> {
    Ok(NoSignals)
}


/// A flag the interrupt and terminate signals set; the loop reads it between cycles, so a batch in flight is stored and acknowledged first.
#[cfg(unix)]
pub fn interrupt_flag() -> Result<Arc<AtomicBool>, ServeError> {
    let flag = Arc::new(AtomicBool::new(false));
    [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]
        .into_iter()
        .try_for_each(|signal| signal_hook::flag::register(signal, Arc::clone(&flag)).map(|_id| ()))
        .map_err(ServeError::Signals)?;
    Ok(flag)
}


#[cfg(not(unix))]
pub fn interrupt_flag() -> Result<Arc<AtomicBool>, ServeError> {
    Ok(Arc::new(AtomicBool::new(false)))
}


/// Starts the service on the settings file named by the single argument and runs until `stop` or `cap` cycles.
pub fn run(arguments: &[String], stop: &StopFn, cap: u64) -> Result<Ended, ServeError> {
    let settings_file = match arguments {
        [file] => Ok(Path::new(file)),
        _ => Err(ServeError::Usage),
    }?;
    let first = load_settings(settings_file)?;
    run_from(settings_file, first, stop, cap)
}


/// Runs on settings the caller already read: that one value gives the audit path, the first settings and the start-only baseline.
pub fn run_from(settings_file: &Path, baseline: IngestSettings, stop: &StopFn, cap: u64) -> Result<Ended, ServeError> {
    let audit_path = baseline.audit_file.clone().ok_or(ServeError::NoAuditFile)?;
    let audit_log = Arc::new(open_file_log(&audit_path)?);
    let engine = Arc::new(open_settings_from(settings_file.to_path_buf(), baseline, boxed_reload_audit(&audit_log))?);
    let _settings_signals = keep_signals(&engine)?;
    let batcher = new_batcher(
        Arc::clone(&engine),
        clickhouse_sink(Arc::clone(&engine)),
        Box::new(system_clock),
        Box::new(real_sleep),
    );
    let mut pipeline = new_pipeline(batcher, nats_wiring(Arc::clone(&engine))?);
    let _settings_watch = watch_files(Arc::clone(&engine), &[settings_file.to_path_buf()], DEBOUNCE)?;
    info!("ostyr-siem-ingest serving");
    let summary = run_loop_capped(&mut pipeline, stop, cap);
    if summary.cycles >= cap && !stop() {
        let cycles = summary.cycles;
        warn!(cycles, "ostyr-siem-ingest cycle cap reached, restart requested");
        Ok(Ended::CycleCap(summary))
    } else {
        let cycles = summary.cycles;
        info!(cycles, "ostyr-siem-ingest stopped");
        Ok(Ended::Stopped(summary))
    }
}


/// The whole program: logs on stderr, the final counts on stdout, the exit code from `exit_code`.
pub fn execute(arguments: &[String]) -> u8 {
    let result = start(arguments);
    if let Ok(Ended::Stopped(summary) | Ended::CycleCap(summary)) = &result {
        write_line(&mut stdout(), &format!("{summary:?}"));
    }
    if let Err(error) = &result {
        write_line(&mut stderr(), &error.to_string());
    }
    exit_code(&result)
}


/// Installs the log subscriber and the signal flag, then runs.
pub fn start(arguments: &[String]) -> Result<Ended, ServeError> {
    let directives = std::env::var(RUST_LOG).ok();
    let subscriber = build_subscriber(stderr, directives.as_deref()).map_err(ServeError::LogFilter)?;
    tracing::subscriber::set_global_default(subscriber).map_err(ServeError::Subscriber)?;
    let flag = interrupt_flag()?;
    let stop = move || flag.load(Ordering::SeqCst);
    run(arguments, &stop, MAX_LOOP_CYCLES)
}


/// Writes one line to the given output; a failed write is logged, never swallowed.
pub fn write_line(output: &mut dyn Write, line: &str) {
    if let Err(error) = writeln!(output, "{line}") {
        warn!(%error, "an output line could not be written");
    }
}
