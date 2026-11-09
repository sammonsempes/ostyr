use crate::error::PgError;
use crate::password::read_limited;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::path::Path;


pub const MAX_CA_BYTES: u64 = 256 * 1024;


/// The trust store is the CA file alone: no platform or Mozilla roots.
pub fn load_roots(ca_file: &Path) -> Result<RootCertStore, PgError> {
    let name = ca_file.display().to_string();
    let bytes = read_limited(ca_file, MAX_CA_BYTES)?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| PgError::Pem { file: name.clone(), source })?;
    let mut roots = RootCertStore::empty();
    certificates.into_iter().try_for_each(|certificate| roots.add(certificate))?;
    if roots.is_empty() {
        Err(PgError::NoCertificate { file: name })
    } else {
        Ok(roots)
    }
}


/// Certificate and host name are always verified against the CA file; there is no way to relax it.
pub fn client_config(ca_file: &Path) -> Result<ClientConfig, PgError> {
    let roots = load_roots(ca_file)?;
    let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(config)
}
