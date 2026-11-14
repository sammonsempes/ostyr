use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use siem_ingest::clickhouse::new_agent;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::{spawn, JoinHandle};


const HOST: &str = "localhost";


const TOKEN: &str = "Zq7Lm2Xw9Rt4Ky6Vb8Nc3Hd5Fg1Js0Pa7Ue2Oi4W";


const WINDOW: usize = 8;


const STATUS_OK: u16 = 200;


const CHUNK: usize = 4096;


const ZERO: u8 = 0;


const MAX_READS: usize = 100;


const HEADER_END: &str = "\r\n\r\n";


#[derive(Clone, Default)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub struct Server {
    pub port: u16,
    pub handle: JoinHandle<io::Result<String>>,
}


fn serve_tls_once(certificate: &str, key: &str) -> Result<Server, Box<dyn Error>> {
    let certificates = CertificateDer::pem_slice_iter(certificate.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let private_key = PrivateKeyDer::from_pem_slice(key.as_bytes())?;
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = spawn(move || {
        let (stream, _) = listener.accept()?;
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).map_err(io::Error::other)?, stream);
        let mut received = String::new();
        let mut chunk = [ZERO; CHUNK];
        let mut reads = 0;
        while !received.contains(HEADER_END) && reads < MAX_READS {
            reads += 1;
            let count = tls.read(&mut chunk)?;
            received.push_str(&String::from_utf8_lossy(chunk.get(..count).unwrap_or(&[])));
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        tls.flush().map(|()| received)
    });
    Ok(Server { port, handle })
}


#[test]
fn a_trace_subscriber_never_sees_a_bearer_token_from_ureq() -> Result<(), Box<dyn Error>> {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init()
        .map_err(|error| error.to_string())?;
    let generated = generate_simple_self_signed(vec![HOST.to_owned()])?;
    let certificate = generated.cert.pem();
    let server = serve_tls_once(&certificate, &generated.signing_key.serialize_pem())?;
    let agent = new_agent(Some(certificate.as_bytes()), true)?;
    let response = agent
        .get(format!("https://{HOST}:{}/", server.port))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .call()?;
    assert_eq!(response.status().as_u16(), STATUS_OK);
    let received = server.handle.join().map_err(|_| "server thread panicked")??;
    assert!(received.contains(TOKEN));
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("ureq"), "{logged}");
    let leaked = TOKEN
        .as_bytes()
        .windows(WINDOW)
        .find(|window| logged.contains(String::from_utf8_lossy(window).as_ref()));
    assert!(leaked.is_none(), "{logged}");
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    Ok(())
}
