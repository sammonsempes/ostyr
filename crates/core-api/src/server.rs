use crate::config::api_config;
use crate::error::StartupError;
use crate::middleware::rate_key;
use crate::model::{ApiConfig, ConnectionGuard, TlsFiles};
use crate::routes::build_router;
use crate::state::build_state;
use crate::types::{AccessTable, ConnectionTable, ServerHandle, SharedState};
use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Server;
use core_audit::log::check_private;
use core_config::load::load_module;
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
use std::time::Duration;
use tower::service_fn;
use utoipa::openapi::OpenApi as OpenApiDocument;


pub const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];


pub const USAGE: &str = "usage: <module-config.yaml>";


pub fn check_transport(address: SocketAddr, tls: Option<&TlsFiles>) -> Result<(), StartupError> {
    if tls.is_some() || address.ip().is_loopback() {
        Ok(())
    } else {
        Err(StartupError::PlainHttpRefused(address))
    }
}


/// TLS 1.2 and 1.3 only; the private key file must grant nothing to group or other.
pub fn tls_server_config(files: &TlsFiles) -> Result<ServerConfig, StartupError> {
    check_private(&File::open(&files.key)?)?;
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


pub fn with_header_timeout<Acceptor>(mut server: Server<SocketAddr, Acceptor>, timeout: Duration) -> Server<SocketAddr, Acceptor> {
    server.http_builder().http1().timer(TokioTimer::new()).header_read_timeout(timeout);
    server
}


pub async fn serve(config: &ApiConfig, router: Router, handle: ServerHandle) -> Result<(), StartupError> {
    check_transport(config.address, config.tls.as_ref())?;
    let connections = ConnectionTable::default();
    let maximum = config.max_connections_per_source;
    let service = service_fn(move |peer: SocketAddr| {
        let admitted = admit_connection(&connections, peer.ip(), maximum);
        let routed = router.clone();
        async move {
            admitted
                .map(|guard| connection_service(routed, peer, guard))
                .ok_or_else(|| io::Error::other("too many connections from this source"))
        }
    });
    let served = match &config.tls {
        Some(files) => {
            let rustls = RustlsConfig::from_config(Arc::new(tls_server_config(files)?));
            with_header_timeout(
                axum_server::bind_rustls(config.address, rustls).handle(handle),
                config.header_read_timeout,
            )
            .serve(service)
            .await
        }
        None => {
            with_header_timeout(axum_server::bind(config.address).handle(handle), config.header_read_timeout)
                .serve(service)
                .await
        }
    };
    served.map_err(StartupError::from)
}


pub async fn run_module(
    arguments: &[String],
    extra: Router<SharedState>,
    extra_access: AccessTable,
    extra_documents: Vec<OpenApiDocument>,
    handle: ServerHandle,
) -> Result<(), StartupError> {
    match arguments {
        [path] => {
            let config = api_config(&load_module(Path::new(path))?)?;
            check_transport(config.address, config.tls.as_ref())?;
            let state: SharedState = Arc::new(build_state(&config, extra_access, extra_documents)?);
            serve(&config, build_router(state, extra), handle).await
        }
        _ => Err(StartupError::Usage(USAGE.to_owned())),
    }
}
