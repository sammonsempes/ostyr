use crate::error::ChannelError;
use crate::model::{ClientTlsPaths, PrivateKeyPem, ServerTlsPaths, ALPN_H2};
use crate::types::{SharedClientConfig, SharedServerConfig};
use core_audit::log::check_private;
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use secrecy::{ExposeSecret, SecretString};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;


pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(default_provider())
}


/// Reads a private key file, refusing group or other access on Unix.
pub fn read_private_key(path: &Path) -> Result<PrivateKeyPem, ChannelError> {
    let io_error = |source| ChannelError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = File::open(path).map_err(io_error)?;
    check_private(&file).map_err(|source| ChannelError::KeyPermissions {
        path: path.to_path_buf(),
        source,
    })?;
    let mut pem = String::new();
    file.read_to_string(&mut pem).map_err(io_error)?;
    Ok(PrivateKeyPem {
        pem: SecretString::from(pem),
    })
}


pub fn parse_private_key(key: &PrivateKeyPem, path: &Path) -> Result<PrivateKeyDer<'static>, ChannelError> {
    PrivateKeyDer::from_pem_slice(key.pem.expose_secret().as_bytes()).map_err(|source| ChannelError::Pem {
        path: path.to_path_buf(),
        source,
    })
}


pub fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, ChannelError> {
    let pem_error = |source| ChannelError::Pem {
        path: path.to_path_buf(),
        source,
    };
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(pem_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(pem_error)?;
    if certificates.is_empty() {
        Err(ChannelError::NoCertificate { path: path.to_path_buf() })
    } else {
        Ok(certificates)
    }
}


pub fn store_of(certificates: Vec<CertificateDer<'static>>) -> Result<RootCertStore, ChannelError> {
    let mut roots = RootCertStore::empty();
    certificates.into_iter().try_for_each(|certificate| roots.add(certificate))?;
    Ok(roots)
}


pub fn root_store(path: &Path) -> Result<RootCertStore, ChannelError> {
    store_of(read_certificates(path)?)
}


/// The agent CA bundle must hold one certificate: revoked serials are matched without the issuer.
pub fn single_authority(path: &Path) -> Result<Vec<CertificateDer<'static>>, ChannelError> {
    let certificates = read_certificates(path)?;
    if certificates.len() > 1 {
        Err(ChannelError::MultipleAgentCa {
            path: path.to_path_buf(),
            count: certificates.len(),
        })
    } else {
        Ok(certificates)
    }
}


/// TLS 1.3 only, client certificate required and verified against the agent CA.
pub fn server_config(paths: &ServerTlsPaths) -> Result<SharedServerConfig, ChannelError> {
    let certificates = read_certificates(&paths.certificate)?;
    let key = parse_private_key(&read_private_key(&paths.key)?, &paths.key)?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(store_of(single_authority(&paths.agent_ca)?)?), provider()).build()?;
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)?;
    config.alpn_protocols.push(ALPN_H2.to_vec());
    Ok(Arc::new(config))
}


/// TLS 1.3 only, server certificate verified against the platform CA and the server name, client certificate presented.
pub fn client_config(paths: &ClientTlsPaths) -> Result<SharedClientConfig, ChannelError> {
    let certificates = read_certificates(&paths.certificate)?;
    let key = parse_private_key(&read_private_key(&paths.key)?, &paths.key)?;
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])?
        .with_root_certificates(root_store(&paths.platform_ca)?)
        .with_client_auth_cert(certificates, key)?;
    config.alpn_protocols.push(ALPN_H2.to_vec());
    Ok(Arc::new(config))
}
