use crate::client::prepare;
use crate::config::{config_state, load_web_config, tls_files, watched_files, DEFAULT_LIMITS};
use crate::error::WebError;
use crate::model::{ApiClient, WebConfig, WebLimits, WebState, DEFAULT_USER_SESSIONS};
use crate::routes::build_router;
use crate::types::{ClockFn, PendingRuntime, Random};
use arc_swap::ArcSwap;
use axum_server::tls_rustls::RustlsConfig;
use core_api::model::Limits;
use core_api::server::{bind_socket, check_transport, serve_socket};
use core_api::types::{ConnectionTable, ServerHandle};
use core_audit::log::{append_declared, open_file_log};
use core_auth::random::os_random;
use core_config::reload::{ReloadContext, ReloadEngine, Subscriber, RELOAD_DECLARED_KEYS};
use core_config::types::{BoxError, SharedAuditFn};
use core_config::watch::watch_files;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};


pub const RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);


pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);


pub const RELOAD_ACTOR: &str = "web-ui";


pub const RELOAD_TENANT: &str = "platform";


pub const RELOAD_REQUEST_ID: &str = "reload";


pub const CONNECTION_LIMITS: Limits = Limits {
    rate_max_requests: 0,
    rate_window_seconds: 0,
    max_sources: 0,
    max_attempts: 0,
    body_read_timeout: Duration::ZERO,
    max_connections_per_source: 64,
};


static STARTED: LazyLock<Instant> = LazyLock::new(Instant::now);


/// Seconds since the first call: monotonic, so a clock step cannot extend or cut a session.
pub fn monotonic_seconds() -> u64 {
    STARTED.elapsed().as_secs()
}


pub fn new_state(client: ApiClient, limits: WebLimits, clock: ClockFn, random: Random) -> WebState {
    WebState {
        api: ArcSwap::from_pointee(client),
        sessions: Default::default(),
        attempts: Default::default(),
        user_sessions_max: AtomicUsize::new(DEFAULT_USER_SESSIONS),
        limits,
        clock,
        random,
    }
}


/// Listen address and TLS presence are fixed at start; everything else a reload may change.
pub fn validate_reload(startup: &WebConfig, pending: &PendingRuntime, config: &WebConfig) -> Result<(), BoxError> {
    if startup.listen != config.listen {
        Err(WebError::Fixed("listen").into())
    } else if startup.tls.is_some() != config.tls.is_some() {
        Err(WebError::Fixed("tls").into())
    } else {
        let prepared = prepare(config)?;
        *pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(prepared);
        Ok(())
    }
}


/// Swaps in what `validate_reload` prepared: the API client for new calls and the certificate for new handshakes.
pub fn apply_pending(state: &WebState, tls: &Option<RustlsConfig>, pending: &PendingRuntime) {
    let prepared = pending.lock().unwrap_or_else(PoisonError::into_inner).take();
    prepared.into_iter().for_each(|ready| {
        state.api.store(Arc::new(ready.client));
        state.user_sessions_max.store(ready.user_sessions, Ordering::SeqCst);
        tls.iter().zip(ready.tls).for_each(|(handle, config)| handle.reload_from_config(config));
    });
}


pub fn reload_subscriber(startup: WebConfig, state: Arc<WebState>, tls: Option<RustlsConfig>, pending: PendingRuntime) -> Subscriber<WebConfig> {
    let validating = pending.clone();
    Subscriber {
        section: "web-ui".to_owned(),
        validate: Box::new(move |config| validate_reload(&startup, &validating, config)),
        apply: Box::new(move |_config| apply_pending(&state, &tls, &pending)),
    }
}


pub fn audit_into(path: &Path) -> Result<Box<SharedAuditFn>, WebError> {
    let log = Arc::new(open_file_log(path)?);
    Ok(Box::new(move |entry| append_declared(&log, entry, &RELOAD_DECLARED_KEYS)))
}


pub fn reload_context(settings_file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: RELOAD_ACTOR.to_owned(),
        tenant: RELOAD_TENANT.to_owned(),
        module: RELOAD_ACTOR.to_owned(),
        target: settings_file.display().to_string(),
        request_id: RELOAD_REQUEST_ID.to_owned(),
    }
}


/// The engine starts from the configuration already loaded and checked: the file is not read a second time.
pub fn build_engine(
    config: WebConfig,
    settings_file: &Path,
    subscriber: Subscriber<WebConfig>,
    audit: Box<SharedAuditFn>,
) -> ReloadEngine<WebConfig> {
    let loader_file: PathBuf = settings_file.to_path_buf();
    ReloadEngine {
        current: ArcSwap::from_pointee(config),
        loader: Box::new(move || load_web_config(&loader_file)),
        to_state: config_state,
        subscribers: vec![subscriber],
        audit,
        context: reload_context(settings_file),
        gate: Mutex::new(()),
    }
}


/// Serves until `handle` stops the server; the file watch and `SIGHUP` reload the settings meanwhile.
pub async fn serve_web(settings_file: &Path, handle: ServerHandle) -> Result<(), WebError> {
    let config = load_web_config(settings_file)?;
    check_transport(config.listen, tls_files(&config).as_ref())?;
    let prepared = prepare(&config)?;
    let audit = audit_into(&config.audit_file)?;
    let state = Arc::new(new_state(prepared.client, DEFAULT_LIMITS, Box::new(monotonic_seconds), os_random));
    state.user_sessions_max.store(prepared.user_sessions, Ordering::SeqCst);
    let tls = prepared.tls.map(RustlsConfig::from_config);
    let subscriber = reload_subscriber(config.clone(), state.clone(), tls.clone(), PendingRuntime::default());
    let engine = Arc::new(build_engine(config.clone(), settings_file, subscriber, audit));
    let _watch = watch_files(engine.clone(), &watched_files(settings_file, &config), RELOAD_DEBOUNCE)?;
    #[cfg(unix)]
    let _signals = core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])?;
    #[cfg(not(unix))]
    drop(engine);
    let socket = bind_socket(config.listen)?;
    serve_socket(
        socket,
        tls,
        build_router(state),
        handle,
        HEADER_READ_TIMEOUT,
        ConnectionTable::default(),
        Arc::new(ArcSwap::from_pointee(CONNECTION_LIMITS)),
    )
    .await?;
    Ok(())
}
