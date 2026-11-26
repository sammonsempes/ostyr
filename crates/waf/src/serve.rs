use crate::apply::{load_trusted_settings_file, open_apply_audited_with_program, production_program};
use crate::error::ServeError;
use crate::limits::{AUDIT_DECLARED_KEYS, DEBOUNCE_MILLIS, FINAL_NAME, SERVICE_ACTOR, SERVICE_MODULE, SERVICE_REQUEST_ID, SIGNAL_QUEUE};
use crate::model::{Applied, ApplySettings};
use crate::runner::run_with_deadline;
use crate::types::{RunnerFn, SignalSourceFn};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log};
use core_audit::tenant::AUDIT_TENANT;
use core_config::reload::{current_config, reload, ReloadContext, ReloadEngine};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::error::Error;
use std::fs;
use std::io::{self, stderr, Write};
use std::os::raw::c_int;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::{Arc, PoisonError};
use std::thread;
use std::time::Duration;
use tracing::subscriber::{set_global_default, SetGlobalDefaultError};
use tracing::{debug, error, info, Level};


/// The one settings file named on the command line.
pub fn parse_args(arguments: &[String]) -> Result<PathBuf, ServeError> {
    match arguments {
        [settings] => Ok(PathBuf::from(settings)),
        _ => Err(ServeError::Usage),
    }
}


/// Plain logs on stderr (journald or a file), installed as the global default; `log` records are not bridged.
pub fn install_logging() -> Result<(), SetGlobalDefaultError> {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(stderr)
        .with_ansi(false)
        .with_max_level(Level::INFO)
        .finish();
    set_global_default(subscriber)
}


/// Registers SIGHUP, SIGINT and SIGTERM at once, so none of them kills the process, and queues each for the service loop.
pub fn signal_source() -> io::Result<Receiver<c_int>> {
    let mut signals = Signals::new([SIGHUP, SIGINT, SIGTERM])?;
    let (sender, receiver) = sync_channel(SIGNAL_QUEUE);
    thread::spawn(move || signals.forever().take_while(|signal| sender.send(*signal).is_ok()).for_each(drop));
    Ok(receiver)
}


/// Every audit record of this service carries the non-customer tenant `all`.
pub fn service_context(settings_file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: SERVICE_ACTOR.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: SERVICE_MODULE.to_owned(),
        target: settings_file.display().to_string(),
        request_id: SERVICE_REQUEST_ID.to_owned(),
    }
}


/// The append-only audit file as a shared sink.
pub fn open_sink(path: &str) -> Result<Box<SharedAuditFn>, AuditError> {
    open_file_log(Path::new(path)).map(|opened| {
        let log = Arc::new(opened);
        let sink: Box<SharedAuditFn> = Box::new(move |entry| append_declared(&log, entry, &AUDIT_DECLARED_KEYS));
        sink
    })
}


/// The audit file opened is the one the running settings name: both come from reads of the same file, so a swap between them is refused.
pub fn check_audit_path(running: &Applied, opened: &str) -> Result<(), ServeError> {
    (running.settings.audit_file.as_deref() == Some(opened))
        .then_some(())
        .ok_or(ServeError::AuditPathChanged)
}


/// True when both paths name the same file (same device and inode) or the same text; a missing file is only equal by text.
pub fn same_file(left: &str, right: &str) -> bool {
    let identity = |path: &str| fs::metadata(path).map(|meta| (meta.dev(), meta.ino()));
    left == right || matches!((identity(left), identity(right)), (Ok(first), Ok(second)) if first == second)
}


/// The audit file is never the settings file, the routes file or the published `caddy.json`.
pub fn check_audit_distinct(settings_file: &Path, settings: &ApplySettings, audit: &str) -> Result<(), ServeError> {
    let published = format!("{}/{FINAL_NAME}", settings.out_dir);
    let clash = [settings_file.display().to_string(), settings.routes_file.clone(), published]
        .iter()
        .any(|other| same_file(audit, other));
    (!clash).then_some(()).ok_or(ServeError::AuditPathClash)
}


/// Once the audit file exists: refused when any directory above it is `out_dir` by device and inode (symlink, bind mount, subdirectory), never by path text.
pub fn check_audit_resolved(out_dir: &str, audit: &str) -> Result<(), ServeError> {
    let out_identity = fs::metadata(out_dir)
        .map(|meta| (meta.dev(), meta.ino()))
        .inspect_err(|failure| debug!(%failure, "out_dir does not resolve"))
        .ok();
    let resolved_audit = fs::canonicalize(audit).map_err(ServeError::AuditPath)?;
    let inside = out_identity.is_some_and(|identity| {
        resolved_audit
            .ancestors()
            .skip(1)
            .any(|directory| fs::metadata(directory).is_ok_and(|meta| (meta.dev(), meta.ino()) == identity))
    });
    (!inside).then_some(()).ok_or(ServeError::AuditPathClash)
}


/// One reload on SIGHUP; the engine audits it, here only the outcome kind is logged.
pub fn reload_on_hangup(engine: &ReloadEngine<Applied>) {
    let outcome = reload(engine);
    debug!(?outcome, "reload after SIGHUP");
}


/// Applies the routes, then reloads on a file change or SIGHUP until a stop signal arrives; every signal sent from the first call on is queued.
pub fn serve_with_program(settings_file: &Path, program: &Path, runner: RunnerFn, source: &SignalSourceFn) -> Result<(), ServeError> {
    let events = source()?;
    let first = load_trusted_settings_file(settings_file)?;
    let audit_path = first.audit_file.clone().ok_or(ServeError::NoAuditFile)?;
    check_audit_distinct(settings_file, &first, &audit_path)?;
    let sink = open_sink(&audit_path);
    sink.iter().try_for_each(|_| check_audit_resolved(&first.out_dir, &audit_path))?;
    let opened = open_apply_audited_with_program(settings_file, program, runner, sink, service_context(settings_file))?;
    let engine = Arc::new(opened);
    let running = current_config(&engine);
    check_audit_path(&running, &audit_path)?;
    check_audit_distinct(settings_file, &running.settings, &audit_path)?;
    check_audit_resolved(&running.settings.out_dir, &audit_path)?;
    let watched = [PathBuf::from(&running.settings.routes_file), settings_file.to_path_buf()];
    let watcher = watch_files(Arc::clone(&engine), &watched, Duration::from_millis(DEBOUNCE_MILLIS))?;
    info!("ostyr-waf running");
    events.iter().find(|signal| {
        let hangup = *signal == SIGHUP;
        if hangup {
            reload_on_hangup(&engine);
        }
        !hangup
    });
    info!("ostyr-waf stopping");
    drop(watcher);
    let in_flight_reload = engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
    std::mem::forget(in_flight_reload);
    Ok(())
}


/// The production entry: the Caddy program is the const, the wait is the signal wait.
pub fn serve(settings_file: &Path) -> Result<(), ServeError> {
    serve_with_program(settings_file, production_program(), run_with_deadline, &signal_source)
}


/// Logging, arguments, then the service.
pub fn run(arguments: &[String]) -> Result<(), ServeError> {
    install_logging()?;
    serve(&parse_args(arguments)?)
}


/// The error and every cause on one line.
pub fn error_line(failure: &dyn Error) -> String {
    let causes = std::iter::successors(failure.source(), |cause: &&dyn Error| (*cause).source()).map(ToString::to_string);
    std::iter::once(failure.to_string()).chain(causes).collect::<Vec<String>>().join(": ")
}


/// 0 after a stop, else 1 with one line on `report`; a failed write is logged.
pub fn exit_code(result: Result<(), ServeError>, report: &mut dyn Write) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let line = error_line(&failure);
            if let Err(write_failure) = writeln!(report, "ostyr-waf: {line}") {
                error!(%write_failure, "cannot write the error line");
            }
            ExitCode::FAILURE
        }
    }
}


/// The binary's exit.
pub fn main_exit(arguments: Vec<String>) -> ExitCode {
    exit_code(run(&arguments), &mut stderr())
}
