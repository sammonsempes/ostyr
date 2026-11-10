use crate::config::tls_files;
use crate::error::{WebError, MAX_SESSIONS, MAX_USER_SESSIONS};
use crate::model::{ApiClient, ApiSection, Prepared, WebConfig};
use core_api::server::load_tls;
use core_config::parse::read_text_capped;
use reqwest::redirect::Policy;
use reqwest::Client;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;


pub const MAX_CA_BYTES: u64 = 1_048_576;


pub const MAX_CA_CERTIFICATES: usize = 64;


pub const HALF: usize = 2;


pub const ALPN: &[u8] = b"http/1.1";


/// Adds the certificates of one PEM bundle, which must hold at least one and at most `MAX_CA_CERTIFICATES`.
pub fn add_bundle(roots: &mut RootCertStore, path: &Path) -> Result<(), WebError> {
    let file = path.display().to_string();
    let text = read_text_capped(&mut File::open(path)?, &file, MAX_CA_BYTES)?;
    let certificates = CertificateDer::pem_slice_iter(text.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        Err(WebError::NoCertificate { file })
    } else if certificates.len() > MAX_CA_CERTIFICATES {
        Err(WebError::TooManyCertificates {
            file,
            max: MAX_CA_CERTIFICATES,
        })
    } else {
        certificates
            .into_iter()
            .try_for_each(|certificate| roots.add(certificate).map_err(WebError::from))
    }
}


/// Without a CA file the store is empty: only a plain HTTP loopback API works.
pub fn client_tls(ca: Option<&Path>) -> Result<ClientConfig, WebError> {
    let mut roots = RootCertStore::empty();
    ca.iter().try_for_each(|path| add_bundle(&mut roots, path))?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}


/// Logins may use at most half of the pool (one at least), so a login flood cannot starve page loads.
pub fn login_slots(max_connections: usize) -> usize {
    (max_connections / HALF).max(1)
}


/// No proxy, no redirect (the answer of a redirect would be followed with the token), one deadline for the whole call.
pub fn build_client(api: &ApiSection) -> Result<ApiClient, WebError> {
    let deadline = Duration::from_secs(api.timeout_seconds);
    let builder = Client::builder()
        .use_preconfigured_tls(client_tls(api.ca.as_deref())?)
        .no_proxy()
        .redirect(Policy::none())
        .pool_max_idle_per_host(api.max_connections)
        .connect_timeout(deadline);
    let http = builder.timeout(deadline).build()?;
    Ok(ApiClient {
        http,
        base: api.base_url.clone(),
        permits: Arc::new(Semaphore::new(api.max_connections)),
        login_permits: Arc::new(Semaphore::new(login_slots(api.max_connections))),
        deadline,
    })
}


pub fn check_user_sessions(count: usize) -> Result<(), WebError> {
    if (1..=MAX_USER_SESSIONS).contains(&count) {
        Ok(())
    } else {
        Err(WebError::UserSessions)
    }
}


pub fn check_sessions(count: usize) -> Result<(), WebError> {
    if (1..=MAX_SESSIONS).contains(&count) {
        Ok(())
    } else {
        Err(WebError::Sessions)
    }
}


/// Everything a reload needs, built and checked before anything is swapped.
pub fn prepare(config: &WebConfig) -> Result<Prepared, WebError> {
    check_user_sessions(config.max_sessions_per_user)?;
    check_sessions(config.max_sessions)?;
    let tls = tls_files(config)
        .map(|files| load_tls(&files).map(|loaded| Arc::new(loaded.config)))
        .transpose()?;
    Ok(Prepared {
        client: build_client(&config.api)?,
        tls,
        user_sessions: config.max_sessions_per_user,
        sessions: config.max_sessions,
    })
}
