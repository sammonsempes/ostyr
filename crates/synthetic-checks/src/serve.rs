//! The `ostyr-synthetic` service: rounds of one runner (one tenant, one location) until the stop flag is set; logs on stderr, reloads audited in a core-audit file.

use crate::alerting::store_outage_alerts;
use crate::error::ProbeError;
use crate::load::{icmp_host, load_checks};
use crate::model::{Check, CheckFile, CheckKind};
use crate::probe::{
    dns_probe, guarded_addresses, http_probe, icmp_probe, probe_limits, tcp_probe, tls_probe, with_nat64_prefix, HttpRequest, HttpTransports,
    ProbeOutcome, MAX_REDIRECTS, MAX_RESPONSE_BYTES, UNPARSEABLE_TARGET,
};
use crate::round::{new_runner, reload_checks, run_round, RoundContext, RoundReport, Runner};
use crate::target::guard_address_nat64;
use crate::types::{Clock, Connect, Handshake, Ping, Resolve, RootedFetch, Sleep, StartRead, StopSource};
use alerts::error::StoreError;
use alerts::model::Alert;
use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_config::watch::watch_files;
use core_pg::connect::connect_with_driver;
use core_pg::error::PgError;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use metric_alerts::token::shown;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, SystemTimeError, UNIX_EPOCH};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use tracing::{info, warn, Dispatch};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::prelude::*;
use url::{Host, Url};


pub const USAGE: &str = "usage: ostyr-synthetic <service.yaml>";


pub const MODULE: &str = "synthetic-checks";


pub const SETTINGS_REQUEST: &str = "settings";


pub const DEBOUNCE: Duration = Duration::from_millis(300);


pub const MAX_ROUNDS: usize = 1_000_000;


pub const ROUND_CAP_EXIT_CODE: u8 = 75;


pub const FAILURE_EXIT_CODE: u8 = 1;


pub const ROUND_PAUSE: Duration = Duration::from_secs(1);


pub const PAUSE_SLICE: Duration = Duration::from_millis(100);


pub const URL_SCHEME: &str = "https";


pub const FALLBACK_URL_SCHEME: &str = "http";


/// Resolver crates log the probed name and the answer text at ERROR for any DNS owner; the service logs none of their targets.
pub const SILENCED_TARGETS: [&str; 3] = ["hickory_resolver", "hickory_proto", "hickory_net"];


pub const IDLE_SUMMARY_ROUNDS: u64 = 60;


/// Every field is read at start only: a reload that changes one is refused whole; the checks file's contents are the live part.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub tenant: String,
    pub location: String,
    pub checks_file: PathBuf,
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
}


/// One whole snapshot: the service file, the checks, the CA roots read with them and the generation of the checks.
#[derive(Clone)]
pub struct LiveConfig {
    pub settings: ServiceSettings,
    pub checks: CheckFile,
    pub roots: Vec<Vec<u8>>,
    pub generation: u64,
    pub skipped: usize,
}


/// The refusals of the probes: the total, and the names whose last probe was refused by the scope guard.
#[derive(Default)]
pub struct Refusals {
    pub total: AtomicU64,
    pub last: Mutex<BTreeSet<String>>,
}


/// The generation applied to the runner and the newest generation the runner refused (logged once).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Applied {
    pub applied: u64,
    pub refused: u64,
}


/// The last checks seen by the loader and their generation (a changed file gets the next number).
#[derive(Default)]
pub struct Memory {
    pub last: Option<CheckFile>,
    pub generation: u64,
}


/// How `start` ended: the stop flag, or the round cap (the supervisor restarts the process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    Interrupted,
    RoundCap,
}


/// The injected transports of the real probes.
pub struct ProbeTools<'a> {
    pub resolve: &'a Resolve<'a>,
    pub fetch: &'a RootedFetch<'a>,
    pub connect: &'a Connect<'a>,
    pub ping: &'a Ping<'a>,
    pub handshake: &'a Handshake<'a>,
    pub clock: &'a Clock<'a>,
}


/// The round cap, the stop flag and the sleep of one slice of the pause.
pub struct RunControl<'a> {
    pub rounds: usize,
    pub stop: &'a AtomicBool,
    pub sleep: &'a Sleep<'a>,
}


/// One connection of the alerts store and its driver task, aborted on drop so a stuck peer's socket is closed.
pub struct Session {
    pub client: Client,
    pub driver: JoinHandle<()>,
}


impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}


/// The target of a TCP or TLS check after the scope guard, and the name to present.
pub struct Endpoint {
    pub address: crate::target::CheckedAddr,
    pub port: u16,
    pub name: String,
}


pub fn setting_error(field: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: format!("settings.{field}"),
        reason: reason.to_owned(),
    }
}


pub fn validate_service(settings: &ServiceSettings) -> Result<(), ConfigError> {
    if !settings.audit_file.is_absolute() {
        Err(setting_error("audit_file", "must be an absolute path"))
    } else if !settings.pg_settings.is_absolute() {
        Err(setting_error("pg_settings", "must be an absolute path"))
    } else if !settings.checks_file.is_absolute() {
        Err(setting_error("checks_file", "must be an absolute path"))
    } else {
        Ok(())
    }
}


pub fn load_service(file: &Path) -> Result<ServiceSettings, ConfigError> {
    let settings: ServiceSettings = load_file(file)?;
    validate_service(&settings)?;
    Ok(settings)
}


/// Counts and the generation only: no target, no file text and no digest of it reaches the audit.
pub fn live_state(live: &LiveConfig) -> ConfigState {
    [
        ("checks_generation", live.generation.to_string()),
        ("checks", live.checks.checks.len().to_string()),
        ("scope_entries", live.checks.scope.len().to_string()),
        ("checks_skipped", live.skipped.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// Reads the checks and the CA roots once; a changed checks file gets the next generation, an unchanged one keeps it.
pub fn next_generation(memory: &Mutex<Memory>, checks: &CheckFile) -> u64 {
    let mut held = memory.lock().unwrap_or_else(PoisonError::into_inner);
    let changed = held.last.as_ref() != Some(checks);
    if changed {
        held.last = Some(checks.clone());
        held.generation = held.generation.saturating_add(1);
    }
    held.generation
}


/// Any difference in the service file from the start snapshot refuses the whole reload, the checks file's changes included.
pub fn live_loader(file: PathBuf, baseline: ServiceSettings) -> Box<LoaderFn<LiveConfig>> {
    let memory = Mutex::new(Memory::default());
    Box::new(move || {
        let settings = load_service(&file)?;
        if settings != baseline {
            Err(setting_error(
                "start-only",
                "tenant, location, checks_file, pg_settings and audit_file are read at start only, restart the service to change them",
            ))
        } else {
            let (checks, skipped) = skip_refused_literals(load_checks(&settings.checks_file)?);
            let roots =
                crate::http::load_roots(checks.ca_file.as_deref()).map_err(|_refused| setting_error("ca_file", "cannot be read within the caps"))?;
            let generation = next_generation(&memory, &checks);
            Ok(LiveConfig {
                settings,
                checks,
                roots,
                generation,
                skipped,
            })
        }
    })
}


/// The IP literal a check's static target names, parsed as the probe parses it; a DNS check and a host name have none.
pub fn literal_target(check: &Check) -> Option<IpAddr> {
    let host = match check.kind {
        CheckKind::Http => Url::parse(&check.target).ok().and_then(|url| url.host().map(|found| found.to_owned())),
        CheckKind::Tcp | CheckKind::Tls => Url::parse(&format!("{URL_SCHEME}://{}", check.target))
            .ok()
            .and_then(|url| url.host().map(|found| found.to_owned())),
        CheckKind::Icmp => icmp_host(&check.target),
        CheckKind::Dns => None,
    };
    match host {
        Some(Host::Ipv4(address)) => Some(IpAddr::V4(address)),
        Some(Host::Ipv6(address)) => Some(IpAddr::V6(address)),
        _ => None,
    }
}


/// A static literal target outside the scope is a configuration error: the check is dropped, named once per load and counted, never probed or alerted.
pub fn skip_refused_literals(mut file: CheckFile) -> (CheckFile, usize) {
    let before = file.checks.len();
    let scope = file.scope.clone();
    file.checks.retain(|check| {
        let refused = literal_target(check).is_some_and(|address| guard_address_nat64(address, &scope, check.nat64_prefix).is_err());
        if refused {
            let shown_name = shown(&check.name);
            let check_name = shown_name.as_str();
            warn!(check_name, "check skipped: literal target out of scope");
        }
        !refused
    });
    let skipped = before - file.checks.len();
    if skipped > 0 {
        warn!(skipped, "checks skipped at load: literal targets outside the declared scope");
    }
    (file, skipped)
}


/// `baseline` is the one start read: the engine's own first load must equal it or the start is refused.
pub fn open_live(file: &Path, baseline: ServiceSettings, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<LiveConfig>, ConfigError> {
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    };
    open_engine(live_loader(file.to_path_buf(), baseline), live_state, Vec::new(), audit, context)
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


/// A refused target is counted apart; the rest of the reasons are fixed words, never the error text (it can name a resolved address).
pub fn failure_label(failure: &ProbeError) -> &'static str {
    match failure {
        ProbeError::Refused(_) => "refused",
        ProbeError::Timeout { .. } => "timeout",
        ProbeError::Transport(source) | ProbeError::Resolve(source) if source.kind() == std::io::ErrorKind::TimedOut => "timeout",
        _ => "failed",
    }
}


pub fn bad_target() -> ProbeError {
    ProbeError::BadTarget {
        target: UNPARSEABLE_TARGET.to_owned(),
    }
}


/// The port written in a `host:port` target, from the URL parse that gave the host: `https` hides `:443` and `http` hides `:80`, so both are read and a port neither shows is absent.
pub fn explicit_port(url: &Url, target: &str) -> Option<u16> {
    url.port().or_else(|| {
        Url::parse(&format!("{FALLBACK_URL_SCHEME}://{target}"))
            .ok()
            .and_then(|other| other.port())
    })
}


/// The guarded address of a `host:port` target of a TCP or TLS check, parsed as an `https` authority so IP literals are real IPs; TLS defaults to 443, TCP needs its port.
pub fn endpoint(check: &Check, live: &LiveConfig, tools: &ProbeTools) -> Result<Endpoint, ProbeError> {
    let url = Url::parse(&format!("{URL_SCHEME}://{}", check.target)).map_err(|_refused| bad_target())?;
    let host = url.host().ok_or_else(bad_target)?;
    let port = match check.kind {
        CheckKind::Tcp => explicit_port(&url, &check.target),
        _ => url.port_or_known_default(),
    }
    .ok_or_else(bad_target)?;
    let timeout = Duration::from_secs(check.timeout_seconds);
    let address = guarded_addresses(host, &live.checks.scope, check.nat64_prefix, tools.resolve, timeout)?
        .into_iter()
        .next()
        .ok_or(ProbeError::NoAddress)?;
    Ok(Endpoint {
        address,
        port,
        name: url.host_str().ok_or_else(bad_target)?.to_owned(),
    })
}


/// The guarded first address of an ICMP target (an IP literal or a plain host name).
pub fn icmp_address(check: &Check, live: &LiveConfig, tools: &ProbeTools) -> Result<crate::target::CheckedAddr, ProbeError> {
    let parsed = icmp_host(&check.target).ok_or_else(bad_target)?;
    let host = match &parsed {
        Host::Ipv4(address) => Host::Ipv4(*address),
        Host::Ipv6(address) => Host::Ipv6(*address),
        Host::Domain(name) => Host::Domain(name.as_str()),
    };
    let timeout = Duration::from_secs(check.timeout_seconds);
    guarded_addresses(host, &live.checks.scope, check.nat64_prefix, tools.resolve, timeout)?
        .into_iter()
        .next()
        .ok_or(ProbeError::NoAddress)
}


/// One probe of the check's kind through the injected transports, under the check's timeout and the file's scope.
pub fn run_probe(check: &Check, live: &LiveConfig, tools: &ProbeTools) -> Result<ProbeOutcome, ProbeError> {
    let timeout = Duration::from_secs(check.timeout_seconds);
    let limits = with_nat64_prefix(probe_limits(timeout, MAX_RESPONSE_BYTES, MAX_REDIRECTS)?, check.nat64_prefix)?;
    match check.kind {
        CheckKind::Http => {
            let fetch = |request: &HttpRequest, left, caps| (tools.fetch)(request, left, caps, &live.roots);
            let transports = HttpTransports {
                resolve: tools.resolve,
                fetch: &fetch,
                clock: tools.clock,
            };
            http_probe(&check.target, &live.checks.scope, &limits, &transports)
        }
        CheckKind::Dns => dns_probe(&check.target, &limits, tools.resolve, tools.clock),
        CheckKind::Tcp => {
            let reached = endpoint(check, live, tools)?;
            tcp_probe(reached.address, reached.port, &limits, tools.connect, tools.clock)
        }
        CheckKind::Tls => {
            let reached = endpoint(check, live, tools)?;
            tls_probe(reached.address, reached.port, &reached.name, &limits, tools.handshake, tools.clock)
        }
        CheckKind::Icmp => icmp_probe(icmp_address(check, live, tools)?, &limits, tools.ping, tools.clock),
    }
}


/// The runner's `Probe`: success is the probe's own verdict; a failure is logged with the shown check name and a fixed reason, never the target.
pub fn probe_check(check: &Check, live: &LiveConfig, tools: &ProbeTools, refusals: &Refusals) -> bool {
    let name = shown(&check.name);
    let check_name = name.as_str();
    match run_probe(check, live, tools) {
        Ok(done) => {
            note_refusal(refusals, check, false);
            if !done.succeeded {
                info!(check_name, "probe did not succeed");
            }
            done.succeeded
        }
        Err(failure) => {
            let reason = failure_label(&failure);
            note_refusal(refusals, check, reason == "refused");
            info!(check_name, reason, "probe failed");
            false
        }
    }
}


/// Records whether the check's last probe was refused by the scope guard, and counts the refusals.
pub fn note_refusal(refusals: &Refusals, check: &Check, refused: bool) {
    refusals.total.fetch_add(u64::from(refused), Ordering::Relaxed);
    let mut held = refusals.last.lock().unwrap_or_else(PoisonError::into_inner);
    if refused {
        held.insert(check.name.clone());
    } else {
        held.remove(&check.name);
    }
}


pub fn last_refused(refusals: &Refusals, check: &Check) -> bool {
    refusals.last.lock().unwrap_or_else(PoisonError::into_inner).contains(&check.name)
}


/// Applies a new checks generation to the runner once; a refused one is logged once, the old checks stay and `applied` does not move.
pub fn apply_live(runner: &mut Runner, live: &LiveConfig, state: Applied) -> Applied {
    if live.generation == state.applied || live.generation == state.refused {
        state
    } else {
        match reload_checks(runner, &live.checks.checks) {
            Ok(_report) => Applied {
                applied: live.generation,
                ..state
            },
            Err(refusal) => {
                let reason = refusal.to_string();
                warn!(reason, "checks reload refused, old checks kept");
                Applied {
                    refused: live.generation,
                    ..state
                }
            }
        }
    }
}


pub async fn open_session(pg: &PgSettings) -> Result<Session, PgError> {
    connect_with_driver(pg).await.map(|(client, driver)| Session { client, driver })
}


/// Stores through one session under core-pg's connect and statement deadlines; a failed call drops the session so the next round reconnects.
pub fn store_alerts(
    runtime: &Runtime,
    session: &Mutex<Option<Session>>,
    pg: &PgSettings,
    scope: &TenantScope,
    alerts: &[Alert],
) -> Result<usize, StoreError> {
    let mut held = session.lock().unwrap_or_else(PoisonError::into_inner);
    let current = match held.take() {
        Some(open) => open,
        None => runtime.block_on(open_session(pg))?,
    };
    let deadline = Duration::from_secs(pg.statement_timeout_secs);
    let outcome = runtime.block_on(store_outage_alerts(&pg_executor(&current.client, deadline), scope, alerts));
    if outcome.is_ok() {
        *held = Some(current);
    }
    outcome
}


/// A clock before the epoch reads 0 and is logged.
pub fn seconds_since_epoch(reading: Result<Duration, SystemTimeError>) -> u64 {
    match reading {
        Ok(elapsed) => elapsed.as_secs(),
        Err(failure) => {
            let reason = failure.to_string();
            warn!(reason, "the clock is before the epoch");
            0
        }
    }
}


pub fn wall_seconds() -> u64 {
    seconds_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH))
}


/// Sleeps `total` in slices, reading the stop flag before each, so a stop is seen within one slice.
pub fn pause(control: &RunControl, total: Duration) {
    let slices = total.as_millis() / PAUSE_SLICE.as_millis();
    (0..slices)
        .take_while(|_slice| !control.stop.load(Ordering::Relaxed))
        .for_each(|_slice| (control.sleep)(PAUSE_SLICE));
}


/// One `round` line for a round that did something; idle rounds are only counted, with one summary line every `IDLE_SUMMARY_ROUNDS`. Answers the idle count.
pub fn log_round(report: &RoundReport, refused_total: u64, idle: u64) -> u64 {
    let (probed, deferred, stored, pending, dropped) = (report.probed, report.deferred, report.stored, report.pending, report.pending_dropped);
    if probed + deferred + stored + pending + dropped == 0 {
        let counted = idle + 1;
        if counted.is_multiple_of(IDLE_SUMMARY_ROUNDS) {
            info!(counted, "idle rounds: no check was due");
        }
        counted
    } else {
        info!(probed, deferred, stored, pending, dropped, refused_total, idle, "round");
        0
    }
}


/// The rounds: each one reads the live snapshot, applies a new checks generation, probes, stores; the pause is stop-aware and never zero.
pub fn serve_rounds(
    runner: &mut Runner,
    engine: &ReloadEngine<LiveConfig>,
    scope: &TenantScope,
    store: &crate::types::Store<'_>,
    tools: &ProbeTools,
    control: &RunControl,
) -> Finish {
    let refusals = Refusals::default();
    let mut applied = Applied::default();
    let mut idle = 0;
    let limit = control.rounds.min(MAX_ROUNDS);
    (0..limit).take_while(|_round| !control.stop.load(Ordering::Relaxed)).for_each(|_round| {
        let live = current_config(engine);
        applied = apply_live(runner, &live, applied);
        let probe = |check: &Check| probe_check(check, &live, tools, &refusals);
        let refused = |check: &Check| last_refused(&refusals, check);
        let stopped = || control.stop.load(Ordering::Relaxed);
        let context = RoundContext {
            scope,
            clock: tools.clock,
            wall: &wall_seconds,
            probe: &probe,
            refused: &refused,
            store,
            stopped: &stopped,
        };
        let report = run_round(runner, &context);
        idle = log_round(&report, refusals.total.load(Ordering::Relaxed), idle);
        pause(control, ROUND_PAUSE);
    });
    if control.stop.load(Ordering::Relaxed) {
        Finish::Interrupted
    } else {
        warn!("round_cap_reached, exiting so the supervisor restarts the runner");
        Finish::RoundCap
    }
}


pub fn system_resolve(name: &str, left: Duration, cap: usize) -> std::io::Result<Vec<IpAddr>> {
    crate::dns::dns_resolve(None, name, left, cap)
}


#[cfg(unix)]
pub fn keep_signals(engine: &Arc<ReloadEngine<LiveConfig>>) -> std::io::Result<core_config::signal::SignalGuard> {
    core_config::signal::reload_on_signals(Arc::clone(engine), &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
pub fn keep_signals(_engine: &Arc<ReloadEngine<LiveConfig>>) -> std::io::Result<NoSignals> {
    Ok(NoSignals)
}


/// Sets the flag at SIGINT and SIGTERM themselves, so a blocking probe sees a stop that nothing polls.
#[cfg(unix)]
pub fn stop_on_signals() -> std::io::Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    let registered = [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT]
        .iter()
        .try_for_each(|signal| signal_hook::flag::register(*signal, Arc::clone(&stop)).map(|_id| ()));
    registered?;
    Ok(stop)
}


#[cfg(not(unix))]
pub fn stop_on_signals() -> std::io::Result<Arc<AtomicBool>> {
    Ok(Arc::new(AtomicBool::new(false)))
}


/// INFO and above for the service, nothing from the resolver crates.
pub fn log_filter() -> Targets {
    SILENCED_TARGETS
        .iter()
        .fold(Targets::new().with_default(LevelFilter::INFO), |targets, target| {
            targets.with_target(*target, LevelFilter::OFF)
        })
}


pub fn log_dispatch(writer: BoxMakeWriter) -> Dispatch {
    Dispatch::new(
        tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_filter(log_filter()),
        ),
    )
}


pub fn run_service(arguments: &[String], stop_source: StopSource) -> Result<Finish, Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    tracing::dispatcher::set_global_default(log_dispatch(BoxMakeWriter::new(std::io::stderr)))?;
    let stop = stop_source()?;
    start(Path::new(settings_file), MAX_ROUNDS, &stop, &std::thread::sleep)
}


pub fn start(settings_file: &Path, rounds: usize, stop: &AtomicBool, sleep: &Sleep<'_>) -> Result<Finish, Box<dyn Error>> {
    let origin = Instant::now();
    let clock = move || origin.elapsed();
    let tools = ProbeTools {
        resolve: &system_resolve,
        fetch: &crate::http::http_fetch,
        connect: &crate::transport::tcp_connect,
        ping: &crate::transport::icmp_echo,
        handshake: &crate::http::tls_handshake,
        clock: &clock,
    };
    start_with(load_service, settings_file, &RunControl { rounds, stop, sleep }, &tools)
}


/// `first_read` is the one start read; the audit path and the start-only baseline both come from it, and a test swaps the file inside it.
pub fn start_with(first_read: StartRead, settings_file: &Path, control: &RunControl, tools: &ProbeTools) -> Result<Finish, Box<dyn Error>> {
    let baseline = first_read(settings_file)?;
    let scope = tenant_scope(&baseline.tenant)?;
    let mut runner = new_runner(&scope, &baseline.location)?;
    let log = Arc::new(open_file_log(&baseline.audit_file)?);
    let engine = Arc::new(open_live(settings_file, baseline.clone(), boxed_reload_audit(&log))?);
    let watched = [settings_file.to_path_buf(), baseline.checks_file.clone()];
    let _watch = watch_files(Arc::clone(&engine), &watched, DEBOUNCE)?;
    let _signals = keep_signals(&engine)?;
    let pg = load_pg_settings(&baseline.pg_settings)?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let first = runtime.block_on(open_session(&pg))?;
    runtime.block_on(migrate(
        &first.client,
        ALERT_NAMESPACE,
        &ALERT_MIGRATIONS,
        Duration::from_secs(pg.statement_timeout_secs),
    ))?;
    let session = Mutex::new(Some(first));
    let store = |alerts: &[Alert]| store_alerts(&runtime, &session, &pg, &scope, alerts);
    info!("serving");
    Ok(serve_rounds(&mut runner, &engine, &scope, &store, tools, control))
}


/// The exit code of a finished run: 0 after a stop, `ROUND_CAP_EXIT_CODE` at the round cap, `FAILURE_EXIT_CODE` and one line on `out` for an error.
pub fn finish_code(result: Result<Finish, Box<dyn Error>>, out: &mut dyn Write) -> std::io::Result<u8> {
    match result {
        Ok(Finish::Interrupted) => Ok(0),
        Ok(Finish::RoundCap) => Ok(ROUND_CAP_EXIT_CODE),
        Err(failure) => writeln!(out, "{failure}").map(|()| FAILURE_EXIT_CODE),
    }
}
