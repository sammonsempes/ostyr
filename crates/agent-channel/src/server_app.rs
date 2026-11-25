//! Server example logic: replace the revocation file atomically (write a temporary file, then rename it), never edit it in place.
use crate::app::{alerting_audit, debounce, keep_signals, reload_context, shared_log_audit};
use crate::commands::command_source;
use crate::error::AppError;
use crate::limits::system_now;
use crate::model::{Counters, RelayListener, ServerState, ServerTlsPaths, PROXY_HEADER_SECONDS};
use crate::presence::watch_silence;
use crate::revocation::open_revocation_engine;
use crate::server::serve_with_relay;
use crate::services::channel_router;
use crate::settings::{open_settings_engine, settings_of};
use crate::sink::{file_sink, open_event_store};
use crate::tls::server_config;
use crate::types::{EventSink, IncomingConnections, NowFn, ReadySender, ShutdownSignal};
use core_audit::log::open_file_log;
use core_audit::tenant::PLATFORM_TENANT;
use core_config::load::load_file;
use core_config::watch::watch_files;
use futures_util::FutureExt;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;


pub const SERVER_MODULE: &str = "channel_server";


/// The server example configuration; the revocation file must be replaced atomically (write then rename), an in-place edit can be read half written.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFile {
    pub listen: String,
    #[serde(default)]
    pub relay_listen: Option<String>,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub agent_ca: PathBuf,
    pub revocation_file: PathBuf,
    pub settings_file: PathBuf,
    pub audit_file: PathBuf,
    pub events_file: PathBuf,
    pub commands_dir: PathBuf,
}


/// Two listener texts name one address: socket addresses compare parsed (IPv4-mapped folded), host names as text (a clash then fails the bind).
pub fn same_listener(first: &str, second: &str) -> bool {
    match (first.parse::<SocketAddr>(), second.parse::<SocketAddr>()) {
        (Ok(one), Ok(other)) => (one.ip().to_canonical(), one.port()) == (other.ip().to_canonical(), other.port()),
        _ => first == second,
    }
}


/// `relay_listen` is start-only and never the same address as `listen`.
pub fn check_listeners(file: &ServerFile) -> Result<(), AppError> {
    if file.relay_listen.as_deref().is_some_and(|relay| same_listener(relay, &file.listen)) {
        Err(AppError::RelayListenEqualsListen)
    } else {
        Ok(())
    }
}


pub fn load_server_file(path: &Path) -> Result<ServerFile, AppError> {
    let file = load_file::<ServerFile>(path)?;
    check_listeners(&file)?;
    Ok(file)
}


pub async fn bind_server(file: &ServerFile) -> Result<TcpListener, AppError> {
    Ok(TcpListener::bind(&file.listen).await?)
}


/// The relay listener when `relay_listen` is set.
pub async fn bind_relay(file: &ServerFile) -> Result<Option<TcpListener>, AppError> {
    check_listeners(file)?;
    match &file.relay_listen {
        Some(address) => Ok(Some(TcpListener::bind(address).await?)),
        None => Ok(None),
    }
}


/// Serves until `shutdown` completes; settings and revocations reload on file change and on `SIGHUP`, every reload is audited.
pub async fn run_server(
    file: ServerFile,
    listener: TcpListener,
    relay: Option<TcpListener>,
    shutdown: ShutdownSignal,
    events: EventSink,
    ready: Option<ReadySender>,
) -> Result<(), AppError> {
    run_server_with_clock(file, (listener, relay), shutdown, events, Box::new(system_now), ready).await
}


/// The relay connections: empty without a relay listener; an empty `relay_sources` is logged once, every peer is then refused.
pub fn relay_incoming(relay: Option<TcpListener>, state: &ServerState) -> IncomingConnections {
    match relay {
        Some(listener) => {
            if settings_of(state).relay_sources.is_empty() {
                tracing::warn!("relay listener without relay_sources, every peer will be refused");
            }
            Box::pin(TcpListenerStream::new(listener))
        }
        None => Box::pin(tokio_stream::empty()),
    }
}


/// The example sink: the events file of `file`, deduplicated on `(identity, sequence)`.
pub fn file_events(file: &ServerFile) -> Result<EventSink, AppError> {
    Ok(file_sink(Arc::new(Mutex::new(open_event_store(&file.events_file)?))))
}


/// Tells the waiting caller, if any, that the server is about to accept; it takes the two signal guards, so it cannot run before them.
pub fn announce_ready<Settings, Revocations>(ready: Option<ReadySender>, _settings_signals: &Settings, _revocation_signals: &Revocations) {
    if ready.map(|sender| sender.send(())).is_some_and(|sent| sent.is_err()) {
        tracing::warn!("nobody waits for the ready signal");
    }
}


/// `run_server` with the limiter clock injected.
pub async fn run_server_with_clock(
    file: ServerFile,
    listeners: (TcpListener, Option<TcpListener>),
    shutdown: ShutdownSignal,
    events: EventSink,
    now: Box<NowFn>,
    ready: Option<ReadySender>,
) -> Result<(), AppError> {
    let log = Arc::new(open_file_log(&file.audit_file).map_err(|source| AppError::AuditFile {
        path: file.audit_file.clone(),
        source,
    })?);
    let (opened_settings, settings) = open_settings_engine(
        file.settings_file.clone(),
        shared_log_audit(&log),
        reload_context(&file.settings_file, SERVER_MODULE, PLATFORM_TENANT, "settings-reload"),
        listeners.1.is_some(),
    )?;
    let (opened_revocations, revocations) = open_revocation_engine(
        file.revocation_file.clone(),
        alerting_audit(shared_log_audit(&log)),
        reload_context(&file.revocation_file, SERVER_MODULE, PLATFORM_TENANT, "revocation-reload"),
    )?;
    let settings_engine = Arc::new(opened_settings);
    let revocation_engine = Arc::new(opened_revocations);
    let _settings_watch = watch_files(Arc::clone(&settings_engine), std::slice::from_ref(&file.settings_file), debounce())?;
    let _revocation_watch = watch_files(Arc::clone(&revocation_engine), std::slice::from_ref(&file.revocation_file), debounce())?;
    let _settings_signals = keep_signals(settings_engine)?;
    let _revocation_signals = keep_signals(revocation_engine)?;
    let state = Arc::new(ServerState {
        settings,
        counters: Counters::default(),
        load: Mutex::default(),
        events,
        commands: command_source(file.commands_dir.clone()),
        presence: Mutex::default(),
        audit: shared_log_audit(&log),
        now,
    });
    let config = server_config(&ServerTlsPaths {
        certificate: file.certificate,
        key: file.key,
        agent_ca: file.agent_ca,
    })?;
    let (listener, relay) = listeners;
    let relay_listener = RelayListener {
        incoming: relay_incoming(relay, &state),
        header_limit: Duration::from_secs(PROXY_HEADER_SECONDS),
    };
    let stop = shutdown.shared();
    let silence = tokio::spawn(watch_silence(Arc::clone(&state), stop.clone()));
    announce_ready(ready, &_settings_signals, &_revocation_signals);
    serve_with_relay(
        Box::pin(TcpListenerStream::new(listener)),
        relay_listener,
        config,
        channel_router(Arc::clone(&state)),
        state,
        revocations,
        Box::pin(stop),
    )
    .await;
    Ok(silence.await?)
}
