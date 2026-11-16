use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::spawn;


pub const MARKER: &str = "peer-san-marker";


pub const PLAIN_MARKER: &str = "plain-http-marker";


pub const ESCAPE: char = '\u{1b}';


pub const LONG_NAME_BYTES: usize = 60_000;


pub const CONNECTIONS: usize = 4;


pub const MAX_LINE_BYTES: usize = 256;


pub const NO_BYTE: u8 = 0;


pub const MAX_SHOWN_BYTES: usize = 1024;


pub struct Hostile {
    pub port: u16,
    pub ca_pem: String,
}


pub struct Held {
    pub port: u16,
    pub release: Sender<()>,
}


pub fn hostile_names() -> Result<Vec<SanType>, Box<dyn Error>> {
    let long = "a".repeat(LONG_NAME_BYTES);
    Ok(vec![
        SanType::DnsName(Ia5String::try_from(format!("{MARKER}.example"))?),
        SanType::URI(Ia5String::try_from(format!("urn:{MARKER}{ESCAPE}[31m{long}"))?),
    ])
}


pub fn hostile_config() -> Result<(Arc<ServerConfig>, String), Box<dyn Error>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.subject_alt_names = hostile_names()?;
    let certificate = params.signed_by(&key, &Issuer::new(ca_params, ca_key))?;
    let private = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private)?,
    );
    Ok((config, ca.pem()))
}


pub fn hostile_server() -> Result<Hostile, Box<dyn Error>> {
    let (config, ca_pem) = hostile_config()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    spawn(move || {
        listener.incoming().take(CONNECTIONS).for_each(|incoming| {
            let outcome = incoming.and_then(|mut stream| {
                let mut connection = ServerConnection::new(Arc::clone(&config)).map_err(std::io::Error::other)?;
                connection.complete_io(&mut stream).map(|_| ())
            });
            if let Err(error) = outcome {
                tracing::debug!("hostile server ended: {error}");
            }
        });
    });
    Ok(Hostile { port, ca_pem })
}


pub fn read_line(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut byte = [NO_BYTE; 1];
    (0..MAX_LINE_BYTES)
        .try_fold(false, |done, _| {
            if done {
                Ok(true)
            } else {
                stream.read_exact(&mut byte).map(|()| byte == *b"\n")
            }
        })
        .map(|_done| ())
}


pub fn starttls_server() -> Result<Hostile, Box<dyn Error>> {
    let (config, ca_pem) = hostile_config()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    spawn(move || {
        listener.incoming().take(CONNECTIONS).for_each(|incoming| {
            let outcome = incoming.and_then(|mut stream| {
                stream.write_all(b"220 hello\r\n")?;
                read_line(&mut stream)?;
                stream.write_all(b"250-hello\r\n250 STARTTLS\r\n")?;
                read_line(&mut stream)?;
                stream.write_all(b"220 go\r\n")?;
                let mut connection = ServerConnection::new(Arc::clone(&config)).map_err(std::io::Error::other)?;
                connection.complete_io(&mut stream).map(|_| ())
            });
            if let Err(error) = outcome {
                tracing::debug!("starttls server ended: {error}");
            }
        });
    });
    Ok(Hostile { port, ca_pem })
}


pub fn plain_server(reply: &'static [u8]) -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    spawn(move || {
        listener.incoming().take(CONNECTIONS).for_each(|incoming| {
            let outcome = incoming.and_then(|mut stream: TcpStream| stream.write_all(reply));
            if let Err(error) = outcome {
                tracing::debug!("plain server ended: {error}");
            }
        });
    });
    Ok(port)
}


pub fn held_server() -> Result<Held, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let (release, wait): (Sender<()>, Receiver<()>) = channel();
    let keep = Arc::new(Mutex::new(Vec::new()));
    spawn(move || {
        listener.incoming().take(1).for_each(|incoming| {
            if let (Ok(stream), Ok(mut held)) = (incoming, keep.lock()) {
                held.push(stream);
            }
            if let Err(error) = wait.recv() {
                tracing::debug!("held server released: {error}");
            }
        });
    });
    Ok(Held { port, release })
}


pub fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


pub fn is_clean(shown: &str) -> bool {
    !shown.contains(MARKER) && !shown.contains(PLAIN_MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}") && shown.len() < MAX_SHOWN_BYTES
}
