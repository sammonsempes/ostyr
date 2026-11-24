use crate::audit::{append_entry, lifecycle_entry, reload_context, shared_audit, START_ACTION, STOP_ACTION};
use crate::error::RelayError;
use crate::model::{Options, Paths, Runtime, DEBOUNCE_MILLIS};
use crate::server::{run_relay, tcp_accept, tcp_connect};
use crate::settings::{nofile_soft_limit, open_settings_engine};
use crate::types::ShutdownSignal;
use core_audit::log::{continue_log, open_checked, AuditLog, SYSTEM_OPENER};
use core_config::reload::current_config;
use core_config::signal::reload_on_signals;
use core_config::watch::watch_files;
use rustix::fs::{flock, fstat, statat, AtFlags, FlockOperation, CWD};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};


pub fn parse_args(args: &[String]) -> Result<Paths, RelayError> {
    match args {
        [settings, audit] => Ok(Paths {
            settings: PathBuf::from(settings),
            audit: PathBuf::from(audit),
        }),
        _ => Err(RelayError::Usage),
    }
}


/// The relay holds no secret and needs one capability only: a root process is refused.
pub fn refuse_root(euid: u32) -> Result<(), RelayError> {
    if euid == 0 {
        Err(RelayError::Root)
    } else {
        Ok(())
    }
}


/// One writer per audit file: a non-blocking exclusive `flock` on the handle that is then verified and appended to.
pub fn lock_audit(file: &File) -> Result<(), RelayError> {
    flock(file, FlockOperation::NonBlockingLockExclusive).map_err(|errno| RelayError::AuditLocked(io::Error::from(errno)))
}


/// The path must still name the locked handle's inode (device and inode number), else the lock guards a file nobody appends to.
pub fn same_inode(file: &File, path: &Path) -> Result<(), RelayError> {
    let held = fstat(file).map_err(io::Error::from)?;
    let named = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino) {
        Ok(())
    } else {
        Err(RelayError::AuditReplaced)
    }
}


/// Opens the audit file once, locks that handle, then verifies and continues the log through the same handle: the head is read under the lock.
pub fn open_locked_log(path: &Path, opened: &dyn Fn(&File)) -> Result<(AuditLog<File>, File), RelayError> {
    let file = open_checked(path, &SYSTEM_OPENER)?;
    opened(&file);
    lock_audit(&file)?;
    same_inode(&file, path)?;
    let audit_lock = file.try_clone()?;
    Ok((continue_log(file)?, audit_lock))
}


/// Opens the audit log under its lock, then opens the settings engine; the first settings must be valid.
pub fn open_runtime(paths: &Paths, soft: u64) -> Result<Runtime, RelayError> {
    open_runtime_with(paths, soft, &|_| ())
}


/// `opened` runs after the audit file is opened and before it is locked: the test seam for an overlapping relay.
pub fn open_runtime_with(paths: &Paths, soft: u64, opened: &dyn Fn(&File)) -> Result<Runtime, RelayError> {
    let (opened_log, audit_lock) = open_locked_log(&paths.audit, opened)?;
    let log = Arc::new(opened_log);
    let engine = Arc::new(open_settings_engine(
        paths.settings.clone(),
        shared_audit(&log),
        reload_context(&paths.settings),
        soft,
    )?);
    Ok(Runtime {
        log,
        engine,
        audit_lock,
        settings_path: paths.settings.clone(),
    })
}


/// Watches the settings file and `SIGHUP`, audits start and stop (with the number of connections cut), serves on `listener` until `stop`.
pub async fn run_runtime(runtime: Runtime, listener: TcpListener, stop: ShutdownSignal, options: Options) -> Result<(), RelayError> {
    let _watch = watch_files(
        Arc::clone(&runtime.engine),
        std::slice::from_ref(&runtime.settings_path),
        Duration::from_millis(DEBOUNCE_MILLIS),
    )?;
    let _signals = reload_on_signals(Arc::clone(&runtime.engine), &[signal_hook::consts::SIGHUP])?;
    let settings = current_config(&runtime.engine);
    let started = [("listen", settings.listen.to_string()), ("upstream", settings.upstream.to_string())];
    append_entry(&runtime.log, lifecycle_entry(&runtime.settings_path, START_ACTION, &started))?;
    let cut = run_relay(tcp_accept(listener), tcp_connect(), Arc::clone(&runtime.engine), stop, options).await;
    append_entry(
        &runtime.log,
        lifecycle_entry(&runtime.settings_path, STOP_ACTION, &[("cut", cut.to_string())]),
    )?;
    Ok(())
}


pub async fn run_from_args(args: &[String], euid: u32, stop: ShutdownSignal) -> Result<(), RelayError> {
    refuse_root(euid)?;
    let paths = parse_args(args)?;
    let runtime = open_runtime(&paths, nofile_soft_limit())?;
    let listener = TcpListener::bind(current_config(&runtime.engine).listen).await?;
    run_runtime(runtime, listener, stop, Options::default()).await
}


/// Completes on `SIGTERM` or `SIGINT`; both handlers are installed when this returns.
pub fn stop_signals() -> io::Result<ShutdownSignal> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = terminate.recv() => (),
            _ = interrupt.recv() => (),
        }
    }))
}


pub fn exit_code(result: Result<(), RelayError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "relay stopped");
            ExitCode::FAILURE
        }
    }
}


pub async fn run_main(args: &[String], euid: u32) -> Result<(), RelayError> {
    let stop = stop_signals()?;
    run_from_args(args, euid, stop).await
}


pub async fn main_exit(args: Vec<String>) -> ExitCode {
    let subscriber = tracing_subscriber::fmt().with_writer(io::stderr).finish();
    let installed = tracing::subscriber::set_global_default(subscriber).is_ok();
    tracing::debug!(installed, "log subscriber");
    let euid = rustix::process::geteuid().as_raw();
    exit_code(run_main(&args, euid).await)
}
