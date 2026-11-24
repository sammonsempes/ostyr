use crate::cli::Session;
use crate::error::ServiceError;
use crate::limits::{DEBOUNCE_MILLIS, MAX_ROUNDS};
use crate::model::{LoopEnd, Reloader, RoundLoop};
use crate::policy::open_policy;
use crate::service::{
    exit_code, open_settings_engine, read_service_settings, serve_rounds, service_context, service_readback, service_runner, shared_audit,
    validate_settings,
};
use crate::source::open_source;
use crate::types::WaitFn;
use core_audit::log::open_file_log;
use core_config::signal::{reload_on_signals, SignalGuard};
use core_config::watch::watch_files;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::io::{self, Write};
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::debug;


pub const STOP_SIGNALS: [c_int; 2] = [SIGINT, SIGTERM];


pub fn parse_args(args: &[String]) -> Result<PathBuf, ServiceError> {
    match args {
        [settings] => Ok(PathBuf::from(settings)),
        _ => Err(ServiceError::Usage),
    }
}


/// A wait that ends early, reporting a stop, when one of `signals` arrives; the guard closes the stream when dropped.
pub fn signal_waiter(signals: &[c_int]) -> io::Result<(Box<WaitFn<'static>>, SignalGuard)> {
    let mut stream = Signals::new(signals)?;
    let handle = stream.handle();
    let (sender, receiver) = channel();
    thread::spawn(move || {
        stream.forever().for_each(|signal| {
            let sent = sender.send(signal).is_ok();
            debug!(signal, sent, "stop signal");
        });
    });
    let wait = move |interval: Duration| !matches!(receiver.recv_timeout(interval), Err(RecvTimeoutError::Timeout));
    Ok((Box::new(wait), SignalGuard { handle }))
}


/// Starts the service from its one argument and runs the rounds until `wait` reports a stop or `max_rounds` is reached.
pub fn run_service(args: &[String], wait: &WaitFn, max_rounds: u64, report: &mut dyn Write) -> Result<LoopEnd, ServiceError> {
    let settings_path = parse_args(args)?;
    let first = read_service_settings(&settings_path)?;
    validate_settings(&first)?;
    let log = Arc::new(open_file_log(Path::new(&first.audit_file))?);
    let settings_engine = Arc::new(open_settings_engine(
        settings_path.clone(),
        &first,
        shared_audit(&log),
        service_context(&settings_path.display().to_string(), "dns-rpz-service-reload"),
    )?);
    let policy_path = PathBuf::from(&first.policy_file);
    let policy_engine = Arc::new(open_policy(
        policy_path.clone(),
        shared_audit(&log),
        service_context(&first.policy_file, "dns-rpz-reload"),
    )?);
    let debounce = Duration::from_millis(DEBOUNCE_MILLIS);
    let _watch_settings = watch_files(Arc::clone(&settings_engine), std::slice::from_ref(&settings_path), debounce)?;
    let _watch_policy = watch_files(Arc::clone(&policy_engine), std::slice::from_ref(&policy_path), debounce)?;
    let _signals_settings = reload_on_signals(Arc::clone(&settings_engine), &[SIGHUP])?;
    let _signals_policy = reload_on_signals(Arc::clone(&policy_engine), &[SIGHUP])?;
    let rejected = AtomicU64::new(0);
    let open = open_source(&first.ioc_source, &rejected);
    let reload_context = service_context(&first.zone_file, "dns-rpz-zone-reload");
    let audit = shared_audit(&log);
    let reloader = Reloader {
        runner: &service_runner,
        readback: &service_readback,
        audit: &*audit,
        context: &reload_context,
    };
    let clock = OffsetDateTime::now_utc;
    let mut session = Session {
        reloader: &reloader,
        engine: &policy_engine,
        clock: &clock,
        open: &*open,
        rejected: &rejected,
        counter: Path::new(&first.counter_file),
        output: Path::new(&first.zone_file),
        report,
    };
    let failure_context = service_context(&first.zone_file, "dns-rpz-round");
    let round_loop = RoundLoop {
        settings: &settings_engine,
        audit: &*audit,
        context: &failure_context,
    };
    serve_rounds(&mut session, &round_loop, wait, max_rounds)
}


pub fn run_main(args: &[String]) -> Result<LoopEnd, ServiceError> {
    let (wait, _guard) = signal_waiter(&STOP_SIGNALS)?;
    run_service(args, &*wait, MAX_ROUNDS, &mut io::stderr())
}


pub fn main_exit(args: Vec<String>) -> ExitCode {
    let subscriber = tracing_subscriber::fmt().with_writer(io::stderr).finish();
    let installed = tracing::subscriber::set_global_default(subscriber).is_ok();
    debug!(installed, "log subscriber");
    exit_code(run_main(&args))
}
