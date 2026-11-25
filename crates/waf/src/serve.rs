use crate::apply::{load_trusted_settings_file, open_apply_audited_with_program, production_program};
use crate::error::ServeError;
use crate::limits::{AUDIT_DECLARED_KEYS, DEBOUNCE_MILLIS, SERVICE_ACTOR, SERVICE_MODULE, SERVICE_REQUEST_ID};
use crate::model::Applied;
use crate::runner::run_with_deadline;
use crate::types::{InterruptFn, RunnerFn};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log};
use core_audit::tenant::AUDIT_TENANT;
use core_config::reload::{current_config, ReloadContext};
use core_config::signal::reload_on_signals;
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::error::Error;
use std::io::{self, stderr, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::subscriber::{set_global_default, SetGlobalDefaultError};
use tracing::{error, info, Level};


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


/// Returns once SIGINT or SIGTERM arrives.
pub fn wait_for_interrupt() -> io::Result<()> {
    Signals::new([SIGINT, SIGTERM])?.forever().next();
    Ok(())
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


/// Applies the routes, then reloads on a file change or SIGHUP until `wait` returns; the program and the runner are injected for tests.
pub fn serve_with_program(settings_file: &Path, program: &Path, runner: RunnerFn, wait: &InterruptFn) -> Result<(), ServeError> {
    let first = load_trusted_settings_file(settings_file)?;
    let audit_path = first.audit_file.ok_or(ServeError::NoAuditFile)?;
    let opened = open_apply_audited_with_program(settings_file, program, runner, open_sink(&audit_path), service_context(settings_file))?;
    let engine = Arc::new(opened);
    let running = current_config(&engine);
    check_audit_path(&running, &audit_path)?;
    let watched = [PathBuf::from(&running.settings.routes_file), settings_file.to_path_buf()];
    let _watcher = watch_files(Arc::clone(&engine), &watched, Duration::from_millis(DEBOUNCE_MILLIS))?;
    let _signals = reload_on_signals(Arc::clone(&engine), &[SIGHUP])?;
    info!("ostyr-waf running");
    wait()?;
    Ok(())
}


/// The production entry: the Caddy program is the const, the wait is the signal wait.
pub fn serve(settings_file: &Path) -> Result<(), ServeError> {
    serve_with_program(settings_file, production_program(), run_with_deadline, &wait_for_interrupt)
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
