//! Server example logic: replace the revocation file atomically (write a temporary file, then rename it), never edit it in place.
use crate::app::{alerting_audit, debounce, keep_signals, reload_context, shared_log_audit};
use crate::commands::command_source;
use crate::error::AppError;
use crate::limits::system_now;
use crate::model::{Counters, ServerState, ServerTlsPaths};
use crate::presence::watch_silence;
use crate::revocation::open_revocation_engine;
use crate::server::serve;
use crate::services::channel_router;
use crate::settings::open_settings_engine;
use crate::sink::{file_sink, open_event_store};
use crate::tls::server_config;
use crate::types::{EventSink, NowFn, ShutdownSignal};
use core_audit::log::open_file_log;
use core_config::load::load_file;
use core_config::watch::watch_files;
use futures_util::FutureExt;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;


pub const SERVER_MODULE: &str = "channel_server";


pub const SERVER_TENANT: &str = "platform";


/// The server example configuration; the revocation file must be replaced atomically (write then rename), an in-place edit can be read half written.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFile {
    pub listen: String,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub agent_ca: PathBuf,
    pub revocation_file: PathBuf,
    pub settings_file: PathBuf,
    pub audit_file: PathBuf,
    pub events_file: PathBuf,
    pub commands_dir: PathBuf,
}


pub fn load_server_file(path: &Path) -> Result<ServerFile, AppError> {
    Ok(load_file::<ServerFile>(path)?)
}


pub async fn bind_server(file: &ServerFile) -> Result<TcpListener, AppError> {
    Ok(TcpListener::bind(&file.listen).await?)
}


/// Serves until `shutdown` completes; settings and revocations reload on file change and on `SIGHUP`, every reload is audited.
pub async fn run_server(file: ServerFile, listener: TcpListener, shutdown: ShutdownSignal, events: EventSink) -> Result<(), AppError> {
    run_server_with_clock(file, listener, shutdown, events, Box::new(system_now)).await
}


/// The example sink: the events file of `file`, deduplicated on `(identity, sequence)`.
pub fn file_events(file: &ServerFile) -> Result<EventSink, AppError> {
    Ok(file_sink(Arc::new(Mutex::new(open_event_store(&file.events_file)?))))
}


/// `run_server` with the limiter clock injected.
pub async fn run_server_with_clock(
    file: ServerFile,
    listener: TcpListener,
    shutdown: ShutdownSignal,
    events: EventSink,
    now: Box<NowFn>,
) -> Result<(), AppError> {
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let (opened_settings, settings) = open_settings_engine(
        file.settings_file.clone(),
        shared_log_audit(&log),
        reload_context(&file.settings_file, SERVER_MODULE, SERVER_TENANT, "settings-reload"),
    )?;
    let (opened_revocations, revocations) = open_revocation_engine(
        file.revocation_file.clone(),
        alerting_audit(shared_log_audit(&log)),
        reload_context(&file.revocation_file, SERVER_MODULE, SERVER_TENANT, "revocation-reload"),
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
    let stop = shutdown.shared();
    let silence = tokio::spawn(watch_silence(Arc::clone(&state), stop.clone()));
    serve(
        Box::pin(TcpListenerStream::new(listener)),
        config,
        channel_router(Arc::clone(&state)),
        state,
        revocations,
        Box::pin(stop),
    )
    .await;
    Ok(silence.await?)
}
