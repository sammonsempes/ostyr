use crate::error::ExportError;
use crate::syslog::write_frames;
use crate::types::TlsStream;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io;
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use ureq::tls::Certificate;


pub const CLOSE_READ_TIMEOUT_SECS: u64 = 5;


/// With a CA bundle only that CA is trusted (private CA); without one the Mozilla roots are.
pub fn root_store(ca_pem: Option<&[u8]>) -> Result<RootCertStore, ExportError> {
    let mut roots = RootCertStore::empty();
    match ca_pem {
        Some(pem) => {
            let certificate = Certificate::from_pem(pem).map_err(ExportError::Certificate)?;
            roots.add(CertificateDer::from(certificate.der().to_vec()))?;
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(roots)
}


pub fn client_config(ca_pem: Option<&[u8]>) -> Result<Arc<ClientConfig>, ExportError> {
    let roots = root_store(ca_pem)?;
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}


/// Sends close_notify, half-closes TCP, then reads until the peer's close_notify so the kernel sends FIN, not RST, and no queued data is lost.
pub fn close_within(stream: &mut TlsStream, timeout: Duration) -> Result<(), ExportError> {
    stream.conn.send_close_notify();
    write_frames(stream, &[])?;
    let drained = stream
        .sock
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.sock.shutdown(Shutdown::Write))
        .and_then(|()| io::copy(stream, &mut io::sink()).map(drop));
    if let Err(error) = drained {
        tracing::debug!(%error, "syslog close: peer did not finish the TLS shutdown");
    }
    Ok(())
}


pub fn close(stream: &mut TlsStream) -> Result<(), ExportError> {
    close_within(stream, Duration::from_secs(CLOSE_READ_TIMEOUT_SECS))
}


/// `address` is `host:port`; the host part is the name the server certificate must match.
pub fn open_stream(address: &str, config: Arc<ClientConfig>) -> Result<TlsStream, ExportError> {
    let host = address.rsplit_once(':').map_or(address, |(name, _port)| name);
    let server_name = ServerName::try_from(host.to_string()).map_err(|source| ExportError::ServerName {
        name: host.to_string(),
        source,
    })?;
    let connection = ClientConnection::new(config, server_name)?;
    let tcp = TcpStream::connect(address).map_err(|source| ExportError::Io {
        context: format!("syslog connect {address}"),
        source,
    })?;
    Ok(StreamOwned::new(connection, tcp))
}
