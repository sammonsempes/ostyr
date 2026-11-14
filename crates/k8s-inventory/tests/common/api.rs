use crate::apitypes::{Handler, Log};
use k8s_inventory::settings::FetchSettings;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread::spawn;
use tempfile::{tempdir, TempDir};


pub const TOKEN: &str = "tok-SECRET.4711.abcdef";


pub const MAX_CONNECTIONS: usize = 400;


pub const SERVER_NAME: &str = "localhost";


pub const OK: u16 = 200;


pub const CREATED: u16 = 201;


pub const BAD_REQUEST: u16 = 400;


pub const NOT_FOUND: u16 = 404;


pub const RUN_TIMEOUT_MS: u64 = 60_000;


#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub authorization: String,
    pub body: String,
}


pub struct Answer {
    pub status: u16,
    pub location: Option<String>,
    pub body: Vec<u8>,
    pub declared: Option<usize>,
}


pub struct Stub {
    pub port: u16,
    pub ca_pem: String,
    pub log: Log,
}


pub struct Rig {
    pub dir: TempDir,
    pub settings: FetchSettings,
    pub stub: Stub,
}


pub fn answer(status: u16, body: String) -> Answer {
    Answer {
        status,
        location: None,
        body: body.into_bytes(),
        declared: None,
    }
}


pub fn review_answer(allowed: bool) -> Answer {
    answer(CREATED, json!({"status": {"allowed": allowed}}).to_string())
}


pub fn read_head<Stream: Read>(reader: &mut BufReader<Stream>) -> io::Result<Vec<String>> {
    reader
        .by_ref()
        .lines()
        .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
        .collect::<io::Result<Vec<_>>>()
}


pub fn header_of(head: &[String], name: &str) -> String {
    head.iter()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim().to_owned())
        })
        .unwrap_or_else(String::new)
}


pub fn serve_one<Stream: Read + Write>(stream: Stream, handler: &Handler, log: &Log) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let head = read_head(&mut reader)?;
    let length = header_of(&head, "content-length").parse::<usize>().unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let mut first = head
        .first()
        .map(|line| line.split(' '))
        .ok_or_else(|| io::Error::other("empty request"))?;
    let seen = Seen {
        method: first.next().unwrap_or("").to_owned(),
        target: first.next().unwrap_or("").to_owned(),
        authorization: header_of(&head, "authorization"),
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    let reply = handler(&seen);
    log.lock().map_err(|_| io::Error::other("poisoned"))?.push(seen);
    let location = reply.location.map_or_else(String::new, |target| format!("Location: {target}\r\n"));
    let response_head = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n",
        reply.status,
        reply.declared.unwrap_or(reply.body.len())
    );
    let writer = reader.get_mut();
    writer.write_all(response_head.as_bytes())?;
    writer.write_all(&reply.body)?;
    writer.flush()
}


pub fn server_config() -> Result<(String, Arc<ServerConfig>), Box<dyn Error>> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)?;
    Ok((cert.pem(), Arc::new(config)))
}


/// A blocking accept loop over TLS, one request per connection; the thread ends with the test process.
pub fn start(handler: Handler) -> Result<Stub, Box<dyn Error>> {
    let (ca_pem, config) = server_config()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let log: Log = Arc::default();
    let shared = Arc::clone(&log);
    spawn(move || {
        (0..MAX_CONNECTIONS).for_each(|_| {
            let outcome = listener.accept().and_then(|(tcp, _)| {
                let connection = ServerConnection::new(Arc::clone(&config)).map_err(io::Error::other)?;
                serve_one(StreamOwned::new(connection, tcp), &handler, &shared)
            });
            if let Err(error) = outcome {
                tracing::debug!("stub connection ended: {error}");
            }
        });
    });
    Ok(Stub { port, ca_pem, log })
}


pub fn seen_of(stub: &Stub) -> Result<Vec<Seen>, Box<dyn Error>> {
    Ok(stub.log.lock().map_err(|_| "poisoned")?.clone())
}


pub fn write_file(dir: &Path, name: &str, text: &str) -> Result<String, Box<dyn Error>> {
    let path = dir.join(name);
    fs::write(&path, text)?;
    Ok(path.display().to_string())
}


pub fn settings_for(dir: &Path, stub: &Stub) -> Result<FetchSettings, Box<dyn Error>> {
    Ok(FetchSettings {
        api_url: format!("https://{SERVER_NAME}:{}", stub.port),
        ca_file: write_file(dir, "ca.pem", &stub.ca_pem)?.into(),
        token_file: write_file(dir, "token", &format!("{TOKEN}\n"))?.into(),
        tenant: "acme".to_owned(),
        cluster: "prod-1".to_owned(),
        timeout_ms: RUN_TIMEOUT_MS,
        page_size: None,
        max_bytes: None,
        max_run_bytes: None,
        max_pages: None,
        max_total_items: None,
    })
}


pub fn rig(handler: Handler) -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    let stub = start(handler)?;
    let settings = settings_for(dir.path(), &stub)?;
    Ok(Rig { dir, settings, stub })
}


pub fn review_of(seen: &Seen) -> Option<(String, String)> {
    let value = serde_json::from_str::<Value>(&seen.body).ok()?;
    let verb = value.pointer("/spec/resourceAttributes/verb")?.as_str()?.to_owned();
    let resource = value.pointer("/spec/resourceAttributes/resource")?.as_str()?.to_owned();
    Some((verb, resource))
}
