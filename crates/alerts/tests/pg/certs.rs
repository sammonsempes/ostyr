use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;


pub struct Pki {
    pub ca_pem: String,
    pub server: Arc<ServerConfig>,
}


pub fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}


/// A CA and a server certificate for `san`, signed by it.
pub fn make_pki(san: SanType) -> Result<Pki, Box<dyn Error>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_certificate = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::new(Vec::<String>::new())?;
    server_params.subject_alt_names.push(san);
    let server_certificate = server_params.signed_by(&server_key, &issuer)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(server_certificate.der().to_vec())], key)?;
    Ok(Pki {
        ca_pem: ca_certificate.pem(),
        server: Arc::new(server),
    })
}
