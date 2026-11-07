use crate::error::StartupError;
use crate::middleware::rate_key;
use crate::model::{ApiConfig, ConnectionGuard, TlsFiles};
use crate::reload::{build_settings, open_reload, watched_files, RELOAD_DEBOUNCE};
use crate::routes::build_router;
use crate::state::build_state;
use crate::types::{AccessTable, ConnectionTable, LogLevelHandle, ServerHandle, SharedLimits, SharedState};
use arc_swap::ArcSwap;
use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Server;
use core_audit::log::check_private;
use core_config::load::load_module;
use core_config::watch::watch_files;
use hyper_util::rt::TokioTimer;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, PoisonError};
use tower::service_fn;
use utoipa::openapi::OpenApi as OpenApiDocument;


pub const ALPN_PROTOCOLS: [&[u8]; 1] = [b"http/1.1"];


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


/// TLS 1.2 and 1.3 only; the private key file must grant nothing to group or other.
pub fn tls_server_config(files: &TlsFiles) -> Result<ServerConfig, StartupError> {
    open_private(&files.key)?;
    let certificates = CertificateDer::pem_file_iter(&files.certificate)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&files.key)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
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


pub fn with_timeouts<Acceptor>(server: Server<SocketAddr, Acceptor>, config: &ApiConfig) -> Server<SocketAddr, Acceptor> {
    let mut http1_server = server.http1_only();
    http1_server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_read_timeout);
    http1_server
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
    let connections = ConnectionTable::default();
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
            with_timeouts(axum_server::bind_rustls(config.address, rustls).handle(handle), config)
                .serve(service)
                .await
        }
        None => {
            with_timeouts(axum_server::bind(config.address).handle(handle), config)
                .serve(service)
                .await
        }
    };
    served.map_err(StartupError::from)
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


pub async fn run_module(
    arguments: &[String],
    extra: Router<SharedState>,
    extra_access: AccessTable,
    extra_documents: Vec<OpenApiDocument>,
    handle: ServerHandle,
    log: Option<LogLevelHandle>,
) -> Result<(), StartupError> {
    match arguments {
        [path] => {
            let module_file = Path::new(path);
            let settings = build_settings(load_module(module_file)?)?;
            let config = settings.config.clone();
            let state: SharedState = Arc::new(build_state(&config, extra_access, extra_documents)?);
            let tls = settings.tls.clone().map(RustlsConfig::from_config);
            let files = watched_files(module_file, &config);
            let engine = open_reload(&state, settings, module_file, tls.clone(), log)?;
            let _watch = watch_files(Arc::clone(&engine), &files, RELOAD_DEBOUNCE)?;
            #[cfg(unix)]
            let _signals = core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])?;
            serve_live(&config, build_router(state.clone(), extra), handle, tls, state.limits.clone()).await
        }
        _ => Err(StartupError::Usage(USAGE.to_owned())),
    }
}
