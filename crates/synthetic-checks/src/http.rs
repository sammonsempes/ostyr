use crate::probe::{FetchCaps, HttpRequest, HttpResponse, MAX_RESPONSE_BYTES};
use crate::target::probe_socket;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use reqwest::tls::TlsInfo;
use reqwest::{Certificate, Method};
use rustls::crypto::ring::default_provider;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::fs::File;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};


const ROOT_PATH: &str = "/";


const READ_CHUNK: usize = 4096;


const MAX_BODY_READS: u64 = MAX_RESPONSE_BYTES as u64 + 1;


const MAX_CA_FILE_BYTES: u64 = 1_048_576;


const MAX_CA_CERTIFICATES: usize = 64;


static PROVIDER_INSTALLED: OnceLock<bool> = OnceLock::new();


fn install_provider() {
    PROVIDER_INSTALLED.get_or_init(|| {
        let installed = default_provider().install_default().is_ok();
        tracing::debug!(installed, "ring installed as the rustls provider");
        installed
    });
}


#[derive(Clone, Copy)]
struct Target<'a> {
    socket: SocketAddr,
    host: &'a str,
    tls: bool,
    path_and_query: &'a str,
}


struct Exchange {
    response: Response,
    verified: Option<bool>,
}


fn to_io(raw: reqwest::Error) -> io::Error {
    let error = raw.without_url();
    let kind = if error.is_timeout() {
        io::ErrorKind::TimedOut
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, error)
}


fn send(target: &Target, method: Method, left: Duration, roots: &[Vec<u8>], accept_invalid: bool) -> io::Result<Response> {
    install_provider();
    let client = roots
        .iter()
        .try_fold(Client::builder(), |builder, der| {
            Certificate::from_der(der).map(|certificate| builder.add_root_certificate(certificate))
        })
        .map_err(to_io)?
        .no_proxy()
        .redirect(Policy::none())
        .timeout(left)
        .tls_info(true)
        .danger_accept_invalid_certs(accept_invalid)
        .resolve(target.host.trim_start_matches('[').trim_end_matches(']'), target.socket)
        .build()
        .map_err(to_io)?;
    let scheme = if target.tls { "https" } else { "http" };
    client
        .request(
            method,
            format!("{scheme}://{}:{}{}", target.host, target.socket.port(), target.path_and_query),
        )
        .send()
        .map_err(to_io)
}


fn exchange(target: &Target, first: Method, left: Duration, roots: &[Vec<u8>]) -> io::Result<Exchange> {
    let started = Instant::now();
    match send(target, first, left, roots, false) {
        Ok(response) => Ok(Exchange {
            response,
            verified: target.tls.then_some(true),
        }),
        Err(error) if target.tls && error.kind() != io::ErrorKind::TimedOut => {
            let unverified = Target {
                path_and_query: ROOT_PATH,
                ..*target
            };
            let response = send(&unverified, Method::HEAD, left.saturating_sub(started.elapsed()), roots, true).map_err(|retry| {
                tracing::debug!(?retry, "second connection for the leaf certificate failed");
                error
            })?;
            Ok(Exchange {
                response,
                verified: Some(false),
            })
        }
        Err(error) => Err(error),
    }
}


fn leaf(response: &Response, caps: FetchCaps) -> io::Result<Vec<Vec<u8>>> {
    let der = response
        .extensions()
        .get::<TlsInfo>()
        .and_then(TlsInfo::peer_certificate)
        .map(<[u8]>::to_vec)
        .into_iter()
        .filter(|_| caps.certificates > 0)
        .collect::<Vec<Vec<u8>>>();
    der.iter()
        .all(|certificate| certificate.len() <= caps.certificate_bytes)
        .then_some(der)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "certificate above the byte cap"))
}


fn location_header(response: &Response, cap: usize) -> Option<String> {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .map(|value| String::from_utf8_lossy(&value.as_bytes().iter().copied().take(cap.saturating_add(1)).collect::<Vec<u8>>()).into_owned())
}


/// The real `Fetch` (T097E): `left` bounds the headers and each body read; one blocked read may last `left` more (under twice `left`).
pub fn http_fetch(request: &HttpRequest, left: Duration, caps: FetchCaps, roots: &[Vec<u8>]) -> io::Result<HttpResponse> {
    let target = Target {
        socket: probe_socket(request.address, request.port),
        host: &request.host,
        tls: request.tls,
        path_and_query: &request.path_and_query,
    };
    let started = Instant::now();
    let Exchange { response, verified } = exchange(&target, Method::GET, left, roots)?;
    let certificate_chain = leaf(&response, caps)?;
    match verified {
        Some(false) => Ok(HttpResponse {
            status: 0,
            location: None,
            body: Vec::new(),
            certificate_chain,
            certificate_verified: verified,
        }),
        _ => read_response(response, caps, certificate_chain, verified, (started, left)),
    }
}


fn read_step(response: &mut Response, body: &mut Vec<u8>, limit: u64, (started, left): (Instant, Duration)) -> io::Result<bool> {
    (started.elapsed() < left)
        .then_some(())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "the deadline passed while reading the body"))?;
    let before = body.len();
    let want = limit.saturating_sub(before as u64).min(READ_CHUNK as u64) as usize;
    body.resize(before + want, 0);
    let (_, tail) = body.split_at_mut(before);
    let count = response.read(tail)?;
    body.truncate(before + count);
    Ok(count == 0 || body.len() as u64 >= limit)
}


fn read_bounded(mut response: Response, limit: u64, deadline: (Instant, Duration)) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut done = false;
    (0..MAX_BODY_READS)
        .map_while(|_| (!done).then(|| read_step(&mut response, &mut body, limit, deadline).inspect(|finished| done = *finished)))
        .collect::<io::Result<Vec<bool>>>()?;
    Ok(body)
}


fn read_response(
    response: Response,
    caps: FetchCaps,
    certificate_chain: Vec<Vec<u8>>,
    verified: Option<bool>,
    deadline: (Instant, Duration),
) -> io::Result<HttpResponse> {
    let status = response.status().as_u16();
    let location = location_header(&response, caps.location_bytes);
    let limit = (caps.body_bytes as u64).saturating_add(1);
    let body = read_bounded(response, limit, deadline)?;
    Ok(HttpResponse {
        status,
        location,
        body,
        certificate_chain,
        certificate_verified: verified,
    })
}


/// The real `Handshake`: a `HEAD /` to the checked socket whose body is never read; only the leaf certificate is returned.
pub fn tls_handshake(
    socket: SocketAddr,
    server_name: &str,
    left: Duration,
    certificates: usize,
    certificate_bytes: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let target = Target {
        socket,
        host: server_name,
        tls: true,
        path_and_query: ROOT_PATH,
    };
    let caps = FetchCaps {
        body_bytes: 0,
        certificates,
        certificate_bytes,
        location_bytes: 0,
    };
    let Exchange { response, .. } = exchange(&target, Method::HEAD, left, &[])?;
    leaf(&response, caps)
}


/// Reads the CA bundle (PEM) once, so every hop of a probe trusts the same snapshot; no file means no extra root.
pub fn load_roots(ca_file: Option<&str>) -> io::Result<Vec<Vec<u8>>> {
    let mut bytes = Vec::new();
    ca_file
        .map(|path| File::open(Path::new(path)).and_then(|file| file.take(MAX_CA_FILE_BYTES + 1).read_to_end(&mut bytes)))
        .transpose()?;
    (bytes.len() as u64 <= MAX_CA_FILE_BYTES)
        .then_some(())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "CA file above the byte cap"))?;
    let roots = CertificateDer::pem_slice_iter(&bytes)
        .take(MAX_CA_CERTIFICATES + 1)
        .map(|parsed| parsed.map(|der| der.as_ref().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    (roots.len() <= MAX_CA_CERTIFICATES)
        .then_some(roots)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "too many CA certificates"))
}


/// The ready-made `Fetch` for a probe: `roots` come from `load_roots`, read once for the whole probe.
pub fn fetch_with_roots(roots: &[Vec<u8>]) -> impl Fn(&HttpRequest, Duration, FetchCaps) -> io::Result<HttpResponse> + '_ {
    move |request, left, caps| http_fetch(request, left, caps, roots)
}
