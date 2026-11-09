use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::error::Error;
use std::io;
use std::net::TcpListener;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


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


pub struct Silent {
    pub port: u16,
    pub held: JoinHandle<io::Result<()>>,
}


/// Accepts one connection and holds it silent until `release` fires.
pub fn spawn_silent(release: Receiver<()>) -> Result<Silent, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = spawn(move || {
        let (_tcp, _peer) = listener.accept()?;
        release.recv().map_err(io::Error::other)
    });
    Ok(Silent { port, held: handle })
}
