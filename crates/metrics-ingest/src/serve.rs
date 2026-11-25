//! The `ostyr-metrics-ingest` service: stores the host metrics of the event stream until SIGINT or SIGTERM, reloads its settings on file change and SIGHUP.


use crate::cardinality::CardinalityState;
use crate::consume::{clickhouse_store, run_loop, Hooks, MAX_LOOP_CYCLES};
use crate::consumer_settings::{open_engines, validate_audit_file, ConsumerFile, ConsumerSettingsError, OpenError};
use crate::types::StopFlag;
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::model::{NewEntry, Record};
use core_config::error::{ConfigError, WatchError};
use core_config::load::load_file;
use core_config::reload::{bounded_parameter, RELOAD_DECLARED_KEYS};
use core_config::signal::reload_on_signals;
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use siem_ingest::error::NatsError;
use siem_ingest::logging::build_subscriber;
use siem_ingest::nats::nats_wiring;
use std::env::VarError;
use std::fs::File;
use std::io::{self, stderr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{error, warn};


pub const USAGE: &str = "usage: ostyr-metrics-ingest <settings.yaml>";


pub const RUST_LOG: &str = "RUST_LOG";


pub const DEBOUNCE_MILLIS: u64 = 300;


pub const EXIT_STOPPED: u8 = 0;


pub const EXIT_CYCLE_CAP: u8 = 75;


/// Why the loop ended: a stop was asked, or the cycle cap was reached and the supervisor must restart the process.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    Stopped,
    CycleCap,
}


#[derive(Debug, Error)]
pub enum ServeError {
    #[error("{USAGE}")]
    Usage,
    #[error("{0}")]
    Open(#[from] OpenError),
    #[error("{0}")]
    AuditPath(#[from] ConsumerSettingsError),
    #[error("cannot open the audit file: {0}")]
    Audit(#[from] AuditError),
    #[error("cannot watch the settings file: {0}")]
    Watch(#[from] WatchError),
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Nats(#[from] NatsError),
    #[error("cannot register the signal handlers: {0}")]
    Signals(#[from] io::Error),
    #[error("RUST_LOG is not valid: {0}")]
    Directives(String),
    #[error("a log subscriber is already installed")]
    Subscriber(#[from] tracing::subscriber::SetGlobalDefaultError),
}


pub fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
}


/// The process exit status: 0 after a stop, `EXIT_CYCLE_CAP` when the loop reached its cycle cap so the supervisor restarts it.
pub fn exit_status(exit: Exit) -> u8 {
    match exit {
        Exit::Stopped => EXIT_STOPPED,
        Exit::CycleCap => EXIT_CYCLE_CAP,
    }
}


/// A failed append is logged as an alert and returned, so the reload engine keeps the old settings.
pub fn append_logged(log: &AuditLog<File>, entry: NewEntry) -> Result<Record, AuditError> {
    let outcome = append_declared(log, entry, &RELOAD_DECLARED_KEYS);
    if let Err(failure) = &outcome {
        error!(%failure, "ALERT: reload audit append failed");
    }
    outcome
}


/// Appends to the audit file with declared keys and every value cut.
pub fn audit_to_file(log: &Arc<AuditLog<File>>) -> Arc<SharedAuditFn> {
    let shared = Arc::clone(log);
    Arc::new(move |mut entry: NewEntry| {
        entry.parameters = entry
            .parameters
            .iter()
            .map(|(key, value)| (key.clone(), bounded_parameter(key, value)))
            .collect();
        append_logged(&shared, entry)
    })
}


/// Logs to stderr: the operator's `RUST_LOG` directives, the async-nats target dropped.
pub fn install_logging(directives: Option<&str>) -> Result<(), ServeError> {
    let subscriber = build_subscriber(stderr, directives).map_err(|failure| ServeError::Directives(failure.to_string()))?;
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}


/// Raises `stop` when `signal` arrives.
pub fn register_one(signal: i32, stop: &StopFlag) -> io::Result<()> {
    signal_hook::flag::register(signal, Arc::clone(stop)).map(drop)
}


/// SIGINT and SIGTERM raise the returned flag; the loop reads it between two cycles.
pub fn register_stop() -> io::Result<StopFlag> {
    let stop: StopFlag = Arc::new(AtomicBool::new(false));
    let signals = [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM];
    signals.iter().try_for_each(|signal| register_one(*signal, &stop))?;
    Ok(stop)
}


/// The `RUST_LOG` text when it is readable.
pub fn directives_of(variable: &Result<String, VarError>) -> Option<&str> {
    match variable {
        Ok(text) => Some(text.as_str()),
        Err(_) => None,
    }
}


/// Logs a `RUST_LOG` that is set but not unicode, once the subscriber is installed.
pub fn warn_unreadable_directives(variable: &Result<String, VarError>) {
    if matches!(variable, Err(VarError::NotUnicode(_))) {
        warn!("RUST_LOG is not unicode, the default directives apply");
    }
}


/// The whole service as the binary runs it: logging, signals, then the loop with the production cycle cap.
pub fn service(arguments: &[String]) -> Result<Exit, ServeError> {
    let variable = std::env::var(RUST_LOG);
    install_logging(directives_of(&variable))?;
    warn_unreadable_directives(&variable);
    let stop = register_stop()?;
    run(arguments, &stop, MAX_LOOP_CYCLES)
}


pub fn run(arguments: &[String], stop: &StopFlag, max_cycles: u64) -> Result<Exit, ServeError> {
    match arguments {
        [path] => serve_file(Path::new(path), stop, max_cycles),
        _ => Err(ServeError::Usage),
    }
}


/// One read of the file gives the audit path and both engines; the watcher and SIGHUP reload each engine, the loop runs until `stop` or `max_cycles`.
pub fn serve_file(path: &Path, stop: &StopFlag, max_cycles: u64) -> Result<Exit, ServeError> {
    let file = load_file::<ConsumerFile>(path)?;
    validate_audit_file(&file.audit_file)?;
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let engines = open_engines(path.to_path_buf(), file, &audit_to_file(&log))?;
    let debounce = Duration::from_millis(DEBOUNCE_MILLIS);
    let _watch_ingest = watch_files(Arc::clone(&engines.ingest), &[path.to_path_buf()], debounce)?;
    let _watch_limits = watch_files(Arc::clone(&engines.limits), &[path.to_path_buf()], debounce)?;
    let _hangup_ingest = reload_on_signals(Arc::clone(&engines.ingest), &[signal_hook::consts::SIGHUP])?;
    let _hangup_limits = reload_on_signals(Arc::clone(&engines.limits), &[signal_hook::consts::SIGHUP])?;
    let mut wiring = nats_wiring(Arc::clone(&engines.ingest))?;
    let mut state = CardinalityState::default();
    let hooks = Hooks {
        now: &now_nanos,
        sleep: &|delay: Duration| sleep(delay),
        send: &clickhouse_store,
        max_cycles,
    };
    let watched = Arc::clone(stop);
    let is_stopped = move || watched.load(Ordering::SeqCst);
    run_loop(&mut wiring, &engines, &mut state, (&hooks, &is_stopped));
    if stop.load(Ordering::SeqCst) {
        Ok(Exit::Stopped)
    } else {
        warn!(max_cycles, "cycle cap reached, exiting so the supervisor restarts the process");
        Ok(Exit::CycleCap)
    }
}
