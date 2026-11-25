//! The `ostyr-detect` service: runs the detection loop until SIGINT or SIGTERM, reloads on file change and SIGHUP (through `run_service`).


use crate::error::DetectionError;
use crate::logging::service_subscriber;
use crate::run::run_service;
use crate::store::commit_alerts;
use crate::types::{SharedStopFn, StopFlag};
use std::env::VarError;
use std::io::{self, stderr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;


pub const USAGE: &str = "usage: ostyr-detect <detection.yaml>";


pub const RUST_LOG: &str = "RUST_LOG";


pub const STOP_SIGNALS: &[i32] = &[signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM];


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
    Detection(#[from] DetectionError),
    #[error("cannot register the signal handlers: {0}")]
    Signals(#[from] io::Error),
    #[error("RUST_LOG is not valid: {0}")]
    Directives(String),
    #[error("a log subscriber is already installed")]
    Subscriber(#[from] tracing::subscriber::SetGlobalDefaultError),
}


/// The process exit status: 0 after a stop, `EXIT_CYCLE_CAP` when the loop reached its cycle cap so the supervisor restarts it.
pub fn exit_status(exit: Exit) -> u8 {
    match exit {
        Exit::Stopped => EXIT_STOPPED,
        Exit::CycleCap => EXIT_CYCLE_CAP,
    }
}


/// Whether the loop ended on a stop request or on its cycle cap.
pub fn exit_of(stop: &StopFlag) -> Exit {
    if stop.load(Ordering::SeqCst) {
        Exit::Stopped
    } else {
        warn!("cycle cap reached, exiting so the supervisor restarts the process");
        Exit::CycleCap
    }
}


/// Logs to stderr: the operator's `RUST_LOG` directives, the async-nats target dropped, INFO by default. `log` records are not bridged.
pub fn install_logging(directives: Option<&str>) -> Result<(), ServeError> {
    let subscriber = service_subscriber(stderr, directives).map_err(|failure| ServeError::Directives(failure.to_string()))?;
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}


/// Each of `signals` raises the returned flag; the loop reads it between two cycles.
pub fn register_stop(signals: &[i32]) -> io::Result<StopFlag> {
    let stop: StopFlag = Arc::new(AtomicBool::new(false));
    signals
        .iter()
        .try_for_each(|signal| signal_hook::flag::register(*signal, Arc::clone(&stop)).map(drop))?;
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


/// The whole service as the binary runs it: logging, signals, then the loop.
pub fn service(arguments: &[String]) -> Result<Exit, ServeError> {
    service_with(arguments, STOP_SIGNALS)
}


/// `service` with the signals that stop it given, so a test can refuse one.
pub fn service_with(arguments: &[String], signals: &[i32]) -> Result<Exit, ServeError> {
    let variable = std::env::var(RUST_LOG);
    install_logging(directives_of(&variable))?;
    warn_unreadable_directives(&variable);
    let stop = register_stop(signals)?;
    run(arguments, &stop)
}


/// One settings path; `run_service` reads it once for the audit path and the baseline.
pub fn run(arguments: &[String], stop: &StopFlag) -> Result<Exit, ServeError> {
    match arguments {
        [path] => serve_file(Path::new(path), stop),
        _ => Err(ServeError::Usage),
    }
}


pub fn serve_file(path: &Path, stop: &StopFlag) -> Result<Exit, ServeError> {
    let watched = Arc::clone(stop);
    let is_stopped: Box<SharedStopFn> = Box::new(move || watched.load(Ordering::SeqCst));
    run_service(path, is_stopped, commit_alerts)?;
    Ok(exit_of(stop))
}
