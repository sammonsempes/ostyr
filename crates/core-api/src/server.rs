use crate::error::StartupError;
use crate::middleware::rate_key;
use crate::model::{
    ApiConfig, Bound, ConnectionGuard, Current, Listener, ListenerSetup, LoadedTls, Rewatch, ServerStop, StateInputs, TlsFiles, WatchStop,
};
use crate::reload::{apply_log_level, build_settings, content_digest, open_reload, rewatch, watched_files};
use crate::routes::build_router;
use crate::state::build_state;
use crate::types::{AccessTable, ConnectionTable, LogLevelHandle, ModuleParts, ServerHandle, SharedLimits, SharedListener, SharedState};
use arc_swap::ArcSwap;
use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use axum_server::from_tcp;
use axum_server::tls_rustls::{from_tcp_rustls, RustlsConfig};
use axum_server::Server;
use core_audit::log::check_private;
use core_config::load::load_module;
use core_config::model::ModuleConfig;
use core_config::reload::reload;
use hyper_util::rt::TokioTimer;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use socket2::SockRef;
use std::fs::{self, File};
use std::io::{self, Read};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tower::service_fn;
use utoipa::openapi::OpenApi as OpenApiDocument;


pub const ALPN_PROTOCOLS: [&[u8]; 1] = [b"http/1.1"];


pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);


pub const USAGE: &str = "usage: <module-config.yaml>";


pub fn check_transport(address: SocketAddr, tls: Option<&TlsFiles>) -> Result<(), StartupError> {
    if tls.is_some() || address.ip().is_loopback() {
        Ok(())
    } else {
        Err(StartupError::PlainHttpRefused(address))
    }
}


/// Opens a file that must grant nothing to group or other; the refusal names the file.
pub fn open_private(path: &Path) -> Result<File, StartupError> {
    let file = File::open(path)?;
    check_private(&file).map_err(|source| StartupError::InsecureFile {
        file: path.display().to_string(),
        source,
    })?;
    Ok(file)
}


/// TLS 1.2 and 1.3 only; the key is read from the handle whose mode was checked and every digest comes from the bytes parsed.
pub fn load_tls(files: &TlsFiles) -> Result<LoadedTls, StartupError> {
    let mut key_bytes = Vec::new();
    open_private(&files.key)?.read_to_end(&mut key_bytes)?;
    let certificate_bytes = fs::read(&files.certificate)?;
    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(LoadedTls {
        config,
        certificate_digest: content_digest(&certificate_bytes),
        key_digest: content_digest(&key_bytes),
    })
}


pub fn tls_server_config(files: &TlsFiles) -> Result<ServerConfig, StartupError> {
    load_tls(files).map(|loaded| loaded.config)
}


pub fn admit_connection(table: &ConnectionTable, source: IpAddr, maximum: usize) -> Option<ConnectionGuard> {
    let key = rate_key(source);
    let mut connections = table.lock().unwrap_or_else(PoisonError::into_inner);
    let count = connections.entry(key).or_insert(0);
    (*count < maximum).then(|| {
        *count += 1;
        ConnectionGuard {
            table: table.clone(),
            source: key,
        }
    })
}


pub fn connection_service(router: Router, peer: SocketAddr, guard: ConnectionGuard) -> Router {
    router.layer(Extension(ConnectInfo(peer))).layer(Extension(Arc::new(guard)))
}


pub fn with_timeouts<Acceptor>(server: Server<SocketAddr, Acceptor>, header_read_timeout: Duration) -> Server<SocketAddr, Acceptor> {
    let mut http1_server = server.http1_only();
    http1_server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    http1_server
}


/// Binds without accepting yet, so a bind failure is known before anything is swapped.
pub fn bind_socket(address: SocketAddr) -> Result<TcpListener, StartupError> {
    let socket = TcpListener::bind(address)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}


/// Makes the kernel refuse new connections on a socket whose server is draining, which a closed handle alone would not (the server keeps its copy open).
pub fn retire_socket(socket: &TcpListener) {
    SockRef::from(socket)
        .shutdown(Shutdown::Both)
        .unwrap_or_else(|error| tracing::warn!(%error, "cannot close the old listening socket"));
}


/// Serves on an already bound socket until `handle` stops it; must run inside the runtime that will drive it.
pub async fn serve_socket(
    socket: TcpListener,
    tls: Option<RustlsConfig>,
    router: Router,
    handle: ServerHandle,
    header_read_timeout: Duration,
    connections: ConnectionTable,
    limits: SharedLimits,
) -> Result<(), StartupError> {
    let service = service_fn(move |peer: SocketAddr| {
        let admitted = admit_connection(&connections, peer.ip(), limits.load().max_connections_per_source);
        let routed = router.clone();
        async move {
            admitted
                .map(|guard| connection_service(routed, peer, guard))
                .ok_or_else(|| io::Error::other("too many connections from this source"))
        }
    });
    let served = match tls {
        Some(rustls) => {
            with_timeouts(from_tcp_rustls(socket, rustls)?.handle(handle), header_read_timeout)
                .serve(service)
                .await
        }
        None => with_timeouts(from_tcp(socket)?.handle(handle), header_read_timeout).serve(service).await,
    };
    served.map_err(StartupError::from)
}


/// `tls` and `limits` are shared handles: a reload replaces the certificate of new handshakes and the connection cap of new connections.
pub async fn serve_live(
    config: &ApiConfig,
    router: Router,
    handle: ServerHandle,
    tls: Option<RustlsConfig>,
    limits: SharedLimits,
) -> Result<(), StartupError> {
    check_transport(config.address, config.tls.as_ref())?;
    let socket = bind_socket(config.address)?;
    serve_socket(
        socket,
        tls,
        router,
        handle,
        config.header_read_timeout,
        ConnectionTable::default(),
        limits,
    )
    .await
}


/// Serves with the settings of `config` as they are now; `serve_live` is the variant whose limits and certificate can change.
pub async fn serve(config: &ApiConfig, router: Router, handle: ServerHandle) -> Result<(), StartupError> {
    let tls = config
        .tls
        .as_ref()
        .map(|files| tls_server_config(files).map(|loaded| RustlsConfig::from_config(Arc::new(loaded))))
        .transpose()?;
    serve_live(config, router, handle, tls, Arc::new(ArcSwap::from_pointee(config.limits))).await
}


/// A listener with no server yet: `run_module` starts the first one, `stop_listener` and `listening_address` act on the newest.
pub fn new_listener() -> SharedListener {
    Arc::new(Listener {
        state: OnceLock::new(),
        current: Mutex::new(Current {
            handle: ServerHandle::new(),
            bound: None,
            stopped: false,
        }),
        connections: ConnectionTable::default(),
        finished: Notify::new(),
        switched: Notify::new(),
        outcome: Mutex::new(None),
    })
}


pub fn current_handle(listener: &Listener) -> ServerHandle {
    listener.current.lock().unwrap_or_else(PoisonError::into_inner).handle.clone()
}


/// The address the newest server listens on, once it does.
pub async fn listening_address(listener: &Listener) -> Option<SocketAddr> {
    current_handle(listener).listening().await
}


/// Stops the newest server after at most `grace`, and no later reload starts another; `run_module` then returns.
pub fn stop_listener(listener: &Listener, grace: Option<Duration>) {
    let mut current = listener.current.lock().unwrap_or_else(PoisonError::into_inner);
    current.stopped = true;
    current.handle.graceful_shutdown(grace);
}


/// Only the newest generation ends `run_module`; an older one that was drained is expected to end.
pub fn finish(listener: &Listener, generation: u64, result: Result<(), StartupError>) {
    let current = listener.current.lock().unwrap_or_else(PoisonError::into_inner);
    if current.bound.as_ref().is_some_and(|bound| bound.generation == generation) {
        *listener.outcome.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
        listener.finished.notify_one();
    } else {
        result
            .err()
            .iter()
            .for_each(|error| tracing::warn!(%error, generation, "a retired server ended with an error"));
    }
}


pub async fn wait_finished(listener: &Listener) -> Result<(), StartupError> {
    listener.finished.notified().await;
    listener.outcome.lock().unwrap_or_else(PoisonError::into_inner).take().unwrap_or(Ok(()))
}


/// Runs one generation of the server on the runtime of `setup`; its end is reported through `finish`.
pub fn spawn_generation(
    setup: &ListenerSetup,
    socket: TcpListener,
    tls: Option<RustlsConfig>,
    header_read_timeout: Duration,
    handle: ServerHandle,
    generation: u64,
) {
    let listener = setup.listener.clone();
    let serving = serve_socket(
        socket,
        tls,
        setup.router.clone(),
        handle,
        header_read_timeout,
        listener.connections.clone(),
        setup.limits.clone(),
    );
    setup.runtime.spawn(async move {
        let result = serving.await;
        finish(&listener, generation, result);
    });
}


/// Binds the configured address and starts generation 0 on the handle of the listener.
pub fn start_first(setup: &ListenerSetup, config: &ApiConfig, tls: Option<RustlsConfig>) -> Result<(), StartupError> {
    check_transport(config.address, config.tls.as_ref())?;
    let socket = bind_socket(config.address)?;
    let server = socket.try_clone()?;
    let mut current = setup.listener.current.lock().unwrap_or_else(PoisonError::into_inner);
    current.bound = Some(Bound {
        socket,
        tls: tls.clone(),
        address: config.address,
        header_read_timeout: config.header_read_timeout,
        generation: 0,
    });
    spawn_generation(setup, server, tls, config.header_read_timeout, current.handle.clone(), 0);
    Ok(())
}


/// Serves until the newest server stops. A reload may move the listener, add or remove TLS, or change the header timeout in the meantime.
pub async fn run_module(
    arguments: &[String],
    extra: Router<SharedState>,
    extra_access: AccessTable,
    extra_documents: Vec<OpenApiDocument>,
    start_only: &[&'static str],
    listener: SharedListener,
    log: Option<LogLevelHandle>,
) -> Result<(), StartupError> {
    match arguments {
        [path] => {
            let module_file = Path::new(path);
            let loaded = load_module(module_file)?;
            run_loaded(module_file, loaded, (extra, extra_access, extra_documents), start_only, listener, log).await
        }
        _ => Err(StartupError::Usage(USAGE.to_owned())),
    }
}


/// As `run_module` for a module file the caller already read: state, start-only baseline and reload engine all come from `loaded`, never from a second read.
pub async fn run_loaded(
    module_file: &Path,
    loaded: ModuleConfig,
    parts: ModuleParts,
    start_only: &[&'static str],
    listener: SharedListener,
    log: Option<LogLevelHandle>,
) -> Result<(), StartupError> {
    let (extra, extra_access, extra_documents) = parts;
    let settings = build_settings(loaded)?;
    log.iter().for_each(|handle| apply_log_level(handle, &settings));
    let config = settings.config.clone();
    let inputs = StateInputs {
        key: settings.key.clone(),
        compromised: settings.compromised.clone(),
        oidc: settings.oidc.clone(),
    };
    let state: SharedState = Arc::new(build_state(&config, &inputs, extra_access, extra_documents)?);
    state.forwarders.store(Arc::clone(&settings.forwarders));
    listener.state.get_or_init(|| state.clone());
    let tls = settings.tls.clone().map(RustlsConfig::from_config);
    let setup = ListenerSetup {
        listener: listener.clone(),
        router: build_router(state.clone(), extra),
        limits: state.limits.clone(),
        runtime: Handle::current(),
        rewatch: Arc::new(Rewatch::default()),
    };
    let _stop_watch = WatchStop(setup.rewatch.clone());
    let engine = open_reload(&state, settings, module_file, setup.clone(), log, start_only)?;
    start_first(&setup, &config, tls)?;
    let _stop_server = ServerStop(listener.clone());
    rewatch(&setup.rewatch, watched_files(module_file, &config))?;
    let startup_outcome = reload(&engine);
    tracing::debug!(?startup_outcome, "startup reload");
    #[cfg(unix)]
    let _signals = core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])?;
    #[cfg(not(unix))]
    drop(engine);
    wait_finished(&listener).await
}
