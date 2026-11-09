use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::crypto::ring::default_provider;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


pub const HOST: &str = "localhost";


const CHUNK: usize = 1024;


const END_OF_HEAD: &[u8] = b"\r\n\r\n";


const MAX_REQUEST_BYTES: usize = 8192;


pub enum Behaviour {
    Reply(Vec<u8>),
    Hang,
}


pub struct Pki {
    pub config: Arc<ServerConfig>,
    pub leaf_der: Vec<u8>,
    pub ca_der: Vec<u8>,
    pub ca_pem: String,
}


pub struct Served {
    pub address: SocketAddr,
    handle: JoinHandle<Vec<String>>,
}


fn server_config(leaf: CertificateDer<'static>, key: Vec<u8>) -> Result<Arc<ServerConfig>, Box<dyn Error>> {
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![leaf], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))?;
    Ok(Arc::new(config))
}


pub fn self_signed() -> Result<Pki, Box<dyn Error>> {
    let generated = rcgen::generate_simple_self_signed(vec![HOST.to_owned()])?;
    let leaf_der = generated.cert.der().to_vec();
    Ok(Pki {
        config: server_config(generated.cert.der().clone(), generated.signing_key.serialize_der())?,
        ca_der: leaf_der.clone(),
        ca_pem: generated.cert.pem(),
        leaf_der,
    })
}


pub fn ca_signed() -> Result<Pki, Box<dyn Error>> {
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate()?;
    let leaf = CertificateParams::new(vec![HOST.to_owned()])?.signed_by(&leaf_key, &issuer)?;
    Ok(Pki {
        config: server_config(leaf.der().clone(), leaf_key.serialize_der())?,
        leaf_der: leaf.der().to_vec(),
        ca_der: ca.der().to_vec(),
        ca_pem: ca.pem(),
    })
}


fn read_head<Source: Read>(stream: &mut Source) -> io::Result<String> {
    let mut head = Vec::new();
    let mut buffer = [0u8; CHUNK];
    let mut ended = false;
    while !ended && !head.ends_with(END_OF_HEAD) && head.len() < MAX_REQUEST_BYTES {
        let count = stream.read(&mut buffer)?;
        head.extend_from_slice(buffer.get(..count).ok_or(io::ErrorKind::InvalidData)?);
        ended = count == 0;
    }
    Ok(String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string())
}


fn answer<Duplex: Read + Write>(mut stream: Duplex, behaviour: &Behaviour) -> io::Result<String> {
    let line = match behaviour {
        Behaviour::Reply(bytes) => {
            let line = read_head(&mut stream)?;
            stream.write_all(bytes)?;
            stream.flush()?;
            line
        }
        Behaviour::Hang => {
            io::copy(&mut stream, &mut io::sink())?;
            String::from("hung")
        }
    };
    Ok(line)
}


fn handle(stream: TcpStream, tls: Option<&Arc<ServerConfig>>, behaviour: &Behaviour) -> io::Result<String> {
    match tls {
        Some(config) => answer(
            StreamOwned::new(ServerConnection::new(config.clone()).map_err(io::Error::other)?, stream),
            behaviour,
        ),
        None => answer(stream, behaviour),
    }
}


pub fn serve(tls: Option<Arc<ServerConfig>>, behaviour: Behaviour, connections: usize) -> io::Result<Served> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let handle = spawn(move || {
        (0..connections)
            .map(|_| match listener.accept() {
                Ok((stream, _)) => handle(stream, tls.as_ref(), &behaviour).unwrap_or_else(|error| format!("error: {error}")),
                Err(error) => format!("accept error: {error}"),
            })
            .collect()
    });
    Ok(Served { address, handle })
}


pub fn finish(served: Served) -> Result<Vec<String>, Box<dyn Error>> {
    served.handle.join().map_err(|_| "the server thread panicked".into())
}
