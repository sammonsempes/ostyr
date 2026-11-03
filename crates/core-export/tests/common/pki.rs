use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::error::Error;
use std::sync::Arc;


pub const SERVER_NAME: &str = "localhost";


pub struct TestPki {
    pub ca_pem: String,
    pub server_config: Arc<ServerConfig>,
}


pub fn test_pki() -> Result<TestPki, Box<dyn Error>> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let server_config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)?;
    Ok(TestPki {
        ca_pem: cert.pem(),
        server_config: Arc::new(server_config),
    })
}
