//! The `ostyr-intel` service: every feed polled and loaded into ClickHouse on a schedule until the interrupt (Unix only).

use crate::config::{feeds_loader, feeds_state, feeds_subscriber, validate_feeds, ClickhouseConfig, FeedConfig, FeedsError, FeedsFile};
use crate::error::TaxiiError;
use crate::limits::{MAX_INTERVAL_SECONDS, MAX_ROUNDS, MIN_INTERVAL_SECONDS, ROUND_CAP_EXIT_CODE};
use crate::load::{load_iocs, LoadError, LoadOutcome};
use crate::model::Ioc;
use crate::round::{run_round, RoundHooks};
use crate::run::open_file;
use crate::taxii::{poll_feed, PollOutcome};
use crate::types::{Cursors, StopWaitFn};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log};
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::signal::{reload_on_signals, SignalGuard};
use core_config::types::{LoaderFn, SharedAuditFn};
use serde::Deserialize;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::io;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, OnceLock, PoisonError};
use std::thread;
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


/// `clickhouse.tenant` is read at start only: the first load fixes it (absent included) and a later load that differs is refused with the old file kept.
pub fn check_tenant_baseline(baseline: &OnceLock<Option<String>>, config: &FeedsFile) -> Result<(), ConfigError> {
    let current = config.clickhouse.as_ref().map(|clickhouse| clickhouse.tenant.clone());
    if *baseline.get_or_init(|| current.clone()) == current {
        Ok(())
    } else {
        Err(ConfigError::WatchedFile {
            file: "clickhouse.tenant".to_owned(),
            reason: "read at start only, restart the service to change it".to_owned(),
        })
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


/// The engine over `inner`: the tenant baseline comes from the same parse as the first configuration, which must hold a valid `clickhouse` section.
pub fn service_engine(inner: Box<LoaderFn<FeedsFile>>, audit: Box<SharedAuditFn>, target: &str) -> Result<ReloadEngine<FeedsFile>, ServiceError> {
    let baseline = OnceLock::new();
    let loader: Box<LoaderFn<FeedsFile>> = Box::new(move || {
        let config = inner()?;
        check_tenant_baseline(&baseline, &config)?;
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


/// Rounds one at a time until a stop or the cap; a round in flight finishes, then the reload gate is held to the return, so a reload in flight is audited first.
pub fn serve_rounds(engine: &ReloadEngine<FeedsFile>, interval: Duration, hooks: &ServeHooks, max_rounds: u64) -> LoopEnd {
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
    let _drained = engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
    if stopped {
        LoopEnd::Stopped
    } else {
        LoopEnd::RoundCap
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
            debug!(signal, sent, "stop signal");
        });
    });
    let wait = move |interval: Duration| !matches!(receiver.recv_timeout(interval), Err(RecvTimeoutError::Timeout));
    Ok((Box::new(wait), SignalGuard { handle }))
}


pub fn production_poll(feed: &FeedConfig, cursor: Option<OffsetDateTime>, now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    let started = Instant::now();
    poll_feed(feed, cursor, now, &|| started.elapsed())
}


pub fn production_load(config: &ClickhouseConfig, iocs: &[Ioc], feeds: &[FeedConfig], now: OffsetDateTime) -> Result<LoadOutcome, LoadError> {
    let started = Instant::now();
    load_iocs(config, iocs, feeds, now, &|| started.elapsed())
}


/// Starts the service from its one argument and runs until the interrupt; SIGHUP reloads the feeds file.
pub fn run_main(args: &[String]) -> Result<LoopEnd, ServiceError> {
    let service = open_service(args)?;
    let base = service.settings.feeds_file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    let open = move |path: &Path| open_file(&base.join(path));
    let (wait, _stop_guard) = signal_waiter(&STOP_SIGNALS)?;
    let _reload_guard = reload_on_signals(Arc::clone(&service.engine), &[SIGHUP])?;
    let hooks = ServeHooks {
        round: RoundHooks {
            clock: &OffsetDateTime::now_utc,
            open: &open,
            poll: &production_poll,
            load: &production_load,
        },
        wait: &*wait,
    };
    info!("intel service started");
    Ok(serve_rounds(
        &service.engine,
        Duration::from_secs(service.settings.interval_seconds),
        &hooks,
        MAX_ROUNDS,
    ))
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
