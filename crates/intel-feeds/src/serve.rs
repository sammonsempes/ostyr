//! The `ostyr-intel` service: every feed polled and loaded into ClickHouse on a schedule until the interrupt (Unix only).

use crate::budget::{read_stored, Stored};
use crate::config::{feeds_loader, feeds_state, feeds_subscriber, validate_feeds, ClickhouseConfig, FeedConfig, FeedsError, FeedsFile};
use crate::error::TaxiiError;
use crate::limits::{MAX_INTERVAL_SECONDS, MAX_ROUNDS, MIN_INTERVAL_SECONDS, ROUND_CAP_EXIT_CODE};
use crate::load::{load_iocs, LoadError, LoadOutcome};
use crate::model::Ioc;
use crate::read::ReadError;
use crate::round::{run_round, RoundHooks};
use crate::run::open_file;
use crate::taxii::{poll_feed, PollOutcome};
use crate::types::{Cursors, EndFn, StopWaitFn};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log};
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, reload, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::signal::{SignalGuard, DROP_JOIN_POLLS};
use core_config::types::{LoaderFn, SharedAuditFn};
use serde::Deserialize;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::{Handle, Signals};
use std::io;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{debug, error, info};


pub const MODULE: &str = "intel-feeds";


pub const REQUEST_ID: &str = "intel-feeds-reload";


pub const STOP_SIGNALS: [c_int; 2] = [SIGINT, SIGTERM];


/// Every field is start-only: the feeds file has its own reload path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub feeds_file: PathBuf,
    pub audit_file: PathBuf,
    pub interval_seconds: u64,
}


#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("usage: ostyr-intel <settings.yaml>")]
    Usage,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("feeds_file and audit_file must be absolute paths")]
    Paths,
    #[error("interval_seconds must be within {MIN_INTERVAL_SECONDS}..={MAX_INTERVAL_SECONDS}")]
    Interval,
    #[error("the audit log could not be opened")]
    Audit(#[from] AuditError),
    #[error("the feeds file is invalid")]
    Feeds(#[from] FeedsError),
    #[error("the feeds file has no clickhouse section")]
    NoClickhouse,
    #[error("a signal handler could not be installed")]
    Signals(#[from] io::Error),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopEnd {
    Stopped,
    RoundCap,
}


pub struct Service {
    pub settings: ServiceSettings,
    pub engine: Arc<ReloadEngine<FeedsFile>>,
}


/// The injected edges of the loop: the round's and the interruptible wait.
pub struct ServeHooks<'a> {
    pub round: RoundHooks<'a>,
    pub wait: &'a StopWaitFn<'a>,
    pub end: &'a EndFn<'a>,
}


pub fn parse_args(args: &[String]) -> Result<PathBuf, ServiceError> {
    match args {
        [settings] => Ok(PathBuf::from(settings)),
        _ => Err(ServiceError::Usage),
    }
}


pub fn validate_settings(settings: &ServiceSettings) -> Result<(), ServiceError> {
    if !settings.feeds_file.is_absolute() || !settings.audit_file.is_absolute() {
        Err(ServiceError::Paths)
    } else if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&settings.interval_seconds) {
        Err(ServiceError::Interval)
    } else {
        Ok(())
    }
}


/// The `clickhouse` fields read at start only: where the rows go and who they belong to; a TAXII cursor never outlives a table move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartOnly {
    pub tenant: String,
    pub url: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub database: String,
    pub table: String,
    pub dictionary: String,
}


pub fn start_only_of(config: &FeedsFile) -> Option<StartOnly> {
    config.clickhouse.as_ref().map(|clickhouse| StartOnly {
        tenant: clickhouse.tenant.clone(),
        url: clickhouse.url.clone(),
        password_file: clickhouse.password_file.clone(),
        ca_file: clickhouse.ca_file.clone(),
        database: clickhouse.database.clone(),
        table: clickhouse.table.clone(),
        dictionary: clickhouse.dictionary.clone(),
    })
}


/// The name of the first start-only field that differs, `clickhouse` when the whole section appeared or went.
pub fn changed_field(old: &Option<StartOnly>, new: &Option<StartOnly>) -> Option<&'static str> {
    match (old, new) {
        (Some(before), Some(after)) => {
            if before.tenant != after.tenant {
                Some("clickhouse.tenant")
            } else if before.url != after.url {
                Some("clickhouse.url")
            } else if before.password_file != after.password_file {
                Some("clickhouse.password_file")
            } else if before.ca_file != after.ca_file {
                Some("clickhouse.ca_file")
            } else if before.database != after.database {
                Some("clickhouse.database")
            } else if before.table != after.table {
                Some("clickhouse.table")
            } else if before.dictionary != after.dictionary {
                Some("clickhouse.dictionary")
            } else {
                None
            }
        }
        (None, None) => None,
        _ => Some("clickhouse"),
    }
}


/// The tenant, URL, password file, CA file, database, table and dictionary are fixed by the first load (absent included): a later load that differs is refused with the old file kept.
pub fn check_start_only(baseline: &OnceLock<Option<StartOnly>>, config: &FeedsFile) -> Result<(), ConfigError> {
    let current = start_only_of(config);
    match changed_field(baseline.get_or_init(|| current.clone()), &current) {
        None => Ok(()),
        Some(field) => Err(ConfigError::WatchedFile {
            file: field.to_owned(),
            reason: "read at start only, restart the service to change it".to_owned(),
        }),
    }
}


pub fn reload_context(target: &str) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: target.to_owned(),
        request_id: REQUEST_ID.to_owned(),
    }
}


/// The engine over `inner`: the start-only baseline comes from the same parse as the first configuration, which must hold a valid `clickhouse` section.
pub fn service_engine(inner: Box<LoaderFn<FeedsFile>>, audit: Box<SharedAuditFn>, target: &str) -> Result<ReloadEngine<FeedsFile>, ServiceError> {
    let baseline = OnceLock::new();
    let loader: Box<LoaderFn<FeedsFile>> = Box::new(move || {
        let config = inner()?;
        check_start_only(&baseline, &config)?;
        Ok(config)
    });
    let engine = open_engine(loader, feeds_state, vec![feeds_subscriber()], audit, reload_context(target))?;
    let first = current_config(&engine);
    validate_feeds(&first)?;
    first.clickhouse.as_ref().ok_or(ServiceError::NoClickhouse)?;
    Ok(engine)
}


/// Reads the settings once, opens the audit log at the path of that read and the engine over the feeds file.
pub fn open_service(args: &[String]) -> Result<Service, ServiceError> {
    let settings: ServiceSettings = load_file(&parse_args(args)?)?;
    validate_settings(&settings)?;
    let log = open_file_log(&settings.audit_file)?;
    let audit: Box<SharedAuditFn> = Box::new(move |entry| append_declared(&log, entry, &RELOAD_DECLARED_KEYS));
    let target = settings.feeds_file.display().to_string();
    let engine = Arc::new(service_engine(feeds_loader(settings.feeds_file.clone()), audit, &target)?);
    Ok(Service { settings, engine })
}


/// What is left of the interval after a round that began at `started`; a clock that went back waits the whole interval.
pub fn left_of(interval: Duration, started: OffsetDateTime, finished: OffsetDateTime) -> Duration {
    interval.saturating_sub(Duration::from_secs((finished - started).whole_seconds().max(0).unsigned_abs()))
}


/// Rounds one at a time until a stop or the cap; a round in flight finishes, `end` records the stop (the round cap included, so a SIGHUP after the gate cannot block the join), then the reload gate is taken once and handed to the caller, so no window separates it from the join.
pub fn serve_rounds<'a>(
    engine: &'a ReloadEngine<FeedsFile>,
    interval: Duration,
    hooks: &ServeHooks,
    max_rounds: u64,
) -> (LoopEnd, MutexGuard<'a, ()>) {
    let mut cursors = Cursors::new();
    let stopped = (0..max_rounds)
        .try_fold((), |(), _| {
            let started = (hooks.round.clock)();
            run_round(&current_config(engine), &mut cursors, &hooks.round);
            if (hooks.wait)(left_of(interval, started, (hooks.round.clock)())) {
                Err(())
            } else {
                Ok(())
            }
        })
        .is_err();
    (hooks.end)();
    let drained = engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
    if stopped {
        (LoopEnd::Stopped, drained)
    } else {
        (LoopEnd::RoundCap, drained)
    }
}


/// A guard that only closes its stream: it has no reload thread.
pub fn hand_guard(handle: Handle) -> SignalGuard {
    SignalGuard {
        handle,
        thread: None,
        in_flight: Arc::default(),
        drop_join_polls: DROP_JOIN_POLLS,
    }
}


/// A wait that ends early, reporting a stop, when one of `signals` arrives; the guard closes the stream when dropped.
pub fn signal_waiter(signals: &[c_int]) -> io::Result<(Box<StopWaitFn<'static>>, SignalGuard)> {
    let mut stream = Signals::new(signals)?;
    let handle = stream.handle();
    let (sender, receiver) = channel();
    thread::spawn(move || {
        stream.forever().for_each(|signal| {
            let sent = sender.send(signal).is_ok();
            info!(signal, sent, "stop signal");
        });
    });
    let wait = move |interval: Duration| !matches!(receiver.recv_timeout(interval), Err(RecvTimeoutError::Timeout));
    Ok((Box::new(wait), hand_guard(handle)))
}


pub fn production_poll(feed: &FeedConfig, cursor: Option<OffsetDateTime>, now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    let started = Instant::now();
    poll_feed(feed, cursor, now, &|| started.elapsed())
}


pub fn production_stored(config: &ClickhouseConfig, now: OffsetDateTime) -> Result<Stored, ReadError> {
    read_stored(config, now)
}


pub fn production_load(config: &ClickhouseConfig, iocs: &[Ioc], feeds: &[FeedConfig], now: OffsetDateTime) -> Result<LoadOutcome, LoadError> {
    let started = Instant::now();
    load_iocs(config, iocs, feeds, now, &|| started.elapsed())
}


/// The SIGHUP reload thread: its stream guard, the stop flag (reloads run under its lock) and the thread to join.
pub struct ReloadThread {
    pub guard: SignalGuard,
    pub stopped: Arc<Mutex<bool>>,
    pub thread: JoinHandle<()>,
}


/// A reload that starts only while no stop was recorded; the flag is read under the lock the reload runs in.
pub fn reload_unless_stopped(stopped: &Mutex<bool>, engine: &ReloadEngine<FeedsFile>) -> bool {
    let state = stopped.lock().unwrap_or_else(PoisonError::into_inner);
    let runs = !*state;
    if runs {
        let outcome = reload(engine);
        debug!(?outcome, "reload after signal");
    }
    runs
}


/// Records the stop once any reload in flight has finished its store, publish and audit; none starts after it.
pub fn record_stop(stopped: &Mutex<bool>) {
    let mut state = stopped.lock().unwrap_or_else(PoisonError::into_inner);
    *state = true;
}


/// Passes the wait's answer through, recording the stop first when it is one.
pub fn record_if_stop(stop: bool, stopped: &Mutex<bool>) -> bool {
    if stop {
        record_stop(stopped);
    }
    stop
}


/// A reload per SIGHUP read from a stream opened before the service started, so an early SIGHUP queues instead of killing the process.
pub fn reload_from(mut stream: Signals, engine: Arc<ReloadEngine<FeedsFile>>) -> ReloadThread {
    let guard = hand_guard(stream.handle());
    let stopped = Arc::new(Mutex::new(false));
    let seen = Arc::clone(&stopped);
    let thread = thread::spawn(move || {
        stream.forever().for_each(|signal| {
            let ran = reload_unless_stopped(&seen, &engine);
            debug!(signal, ran, "signal handled");
        });
    });
    ReloadThread { guard, stopped, thread }
}


/// Closes the SIGHUP stream and joins the reload thread, so nothing reloads once this returns.
pub fn join_reload(reload_thread: ReloadThread) {
    let ReloadThread { guard, thread, .. } = reload_thread;
    drop(guard);
    let joined = thread.join().is_ok();
    debug!(joined, "reload thread joined");
}


/// Runs until the interrupt (SIGHUP reloads the feeds file); every signal is registered first, the stop is recorded before the drain and the gate is held to the return.
pub fn run_main(args: &[String]) -> Result<LoopEnd, ServiceError> {
    let hangup = Signals::new([SIGHUP])?;
    let (wait, _stop_guard) = signal_waiter(&STOP_SIGNALS)?;
    let service = open_service(args)?;
    let base = service.settings.feeds_file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    let open = move |path: &Path| open_file(&base.join(path));
    let reload_thread = reload_from(hangup, Arc::clone(&service.engine));
    let stopped = Arc::clone(&reload_thread.stopped);
    let recorder = Arc::clone(&reload_thread.stopped);
    let stopping = move |interval: Duration| record_if_stop((*wait)(interval), &stopped);
    let recording = move || record_stop(&recorder);
    let hooks = ServeHooks {
        round: RoundHooks {
            clock: &OffsetDateTime::now_utc,
            open: &open,
            poll: &production_poll,
            load: &production_load,
            stored: &production_stored,
        },
        wait: &stopping,
        end: &recording,
    };
    info!("intel service started");
    let (ended, _drained) = serve_rounds(
        &service.engine,
        Duration::from_secs(service.settings.interval_seconds),
        &hooks,
        MAX_ROUNDS,
    );
    join_reload(reload_thread);
    Ok(ended)
}


pub fn exit_code(result: Result<LoopEnd, ServiceError>) -> ExitCode {
    match result {
        Ok(LoopEnd::Stopped) => ExitCode::SUCCESS,
        Ok(LoopEnd::RoundCap) => {
            error!("round cap reached, restart the service");
            ExitCode::from(ROUND_CAP_EXIT_CODE)
        }
        Err(failure) => {
            error!(%failure, "intel service stopped");
            ExitCode::FAILURE
        }
    }
}


/// Plain logs on stderr through the global `tracing` subscriber; `log` records are dropped.
pub fn main_exit(args: Vec<String>) -> ExitCode {
    let subscriber = tracing_subscriber::fmt().with_writer(io::stderr).with_ansi(false).finish();
    let installed = tracing::subscriber::set_global_default(subscriber).is_ok();
    debug!(installed, "log subscriber");
    exit_code(run_main(&args))
}
