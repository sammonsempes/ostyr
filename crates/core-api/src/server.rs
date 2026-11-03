use crate::config::api_config;
use crate::error::StartupError;
use crate::model::{ApiConfig, TlsFiles};
use crate::routes::build_router;
use crate::state::build_state;
use crate::types::{AccessTable, ServerHandle, SharedState};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use core_audit::log::check_private;
use core_config::load::load_module;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;


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


pub async fn serve(config: &ApiConfig, router: Router, handle: ServerHandle) -> Result<(), StartupError> {
    check_transport(config.address, config.tls.as_ref())?;
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    let served = match &config.tls {
        Some(files) => {
            let rustls = RustlsConfig::from_config(Arc::new(tls_server_config(files)?));
            axum_server::bind_rustls(config.address, rustls).handle(handle).serve(service).await
        }
        None => axum_server::bind(config.address).handle(handle).serve(service).await,
    };
    served.map_err(StartupError::from)
}


pub async fn run_module(
    arguments: &[String],
    extra: Router<SharedState>,
    extra_access: AccessTable,
    handle: ServerHandle,
) -> Result<(), StartupError> {
    match arguments {
        [path] => {
            let config = api_config(&load_module(Path::new(path))?)?;
            check_transport(config.address, config.tls.as_ref())?;
            let state: SharedState = Arc::new(build_state(&config, extra_access)?);
            serve(&config, build_router(state, extra), handle).await
        }
        _ => Err(StartupError::Usage(USAGE.to_owned())),
    }
}
