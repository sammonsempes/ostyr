use crate::error::ProbeError;
use crate::model::MAX_BODY_EXCERPT_BYTES;
use crate::target::{guard_address, probe_socket, CheckedAddr};
use crate::types::{Clock, Connect, Fetch, Handshake, Resolve};
use ipnet::IpNet;
use std::net::IpAddr;
use std::time::Duration;
use url::{Host, Url};


pub const MAX_REDIRECTS: usize = 5;


pub const MAX_RESPONSE_BYTES: usize = 1_048_576;


pub const MAX_CHAIN_CERTS: usize = 10;


pub const MAX_CERT_BYTES: usize = 16_384;


pub const MAX_DNS_ANSWERS: usize = 64;


pub const FIRST_SUCCESS_STATUS: u16 = 200;


pub const FIRST_REDIRECT_STATUS: u16 = 300;


pub const FIRST_ERROR_STATUS: u16 = 400;


/// Limits of one probe: the hard deadline, the response cap and the redirect cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeLimits {
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub max_redirects: usize,
}


/// What a probe records; the body is never kept in full and `certificate_chain` (DER, leaf first) is empty unless TLS was used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub succeeded: bool,
    pub body_excerpt: String,
    pub certificate_chain: Vec<Vec<u8>>,
}


/// The injected transports of an HTTP probe.
#[derive(Clone, Copy)]
pub struct HttpTransports<'a> {
    pub resolve: &'a Resolve<'a>,
    pub fetch: &'a Fetch<'a>,
    pub clock: &'a Clock<'a>,
}


/// One HTTP request: connect to `address`, never to `host`, which only fills the Host header and the TLS server name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub address: CheckedAddr,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub path_and_query: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub location: Option<String>,
    pub body: Vec<u8>,
    pub certificate_chain: Vec<Vec<u8>>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopState {
    Follow(Url),
    Done(HttpResponse),
}


/// The deadline as the injected clock reads it: `started` and `limit` are offsets on that clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    pub started: Duration,
    pub limit: Duration,
}


pub fn start_deadline(clock: &Clock<'_>, limit: Duration) -> Deadline {
    Deadline { started: clock(), limit }
}


/// Time left before the deadline; a deadline that is reached counts as passed.
pub fn remaining(clock: &Clock<'_>, deadline: &Deadline) -> Result<Duration, ProbeError> {
    deadline
        .limit
        .checked_sub(clock().saturating_sub(deadline.started))
        .filter(|left| !left.is_zero())
        .ok_or(ProbeError::Timeout { limit: deadline.limit })
}


pub fn latency_ms(clock: &Clock<'_>, deadline: &Deadline) -> u64 {
    clock().saturating_sub(deadline.started).as_millis() as u64
}


/// The first bytes of a body, control characters escaped, capped at `MAX_BODY_EXCERPT_BYTES` after escaping.
pub fn escaped_excerpt(body: &[u8]) -> String {
    let mut used = 0;
    String::from_utf8_lossy(body)
        .chars()
        .map(|character| {
            if character.is_control() {
                character.escape_default().collect::<String>()
            } else {
                character.to_string()
            }
        })
        .take_while(|piece| {
            used += piece.len();
            used <= MAX_BODY_EXCERPT_BYTES
        })
        .collect()
}


/// Resolves the host of a URL (an IP literal needs no lookup) and guards every address: one refused address refuses the host.
pub fn guarded_addresses(host: Host<&str>, scope: &[IpNet], resolve: &Resolve<'_>) -> Result<Vec<CheckedAddr>, ProbeError> {
    let addresses = match host {
        Host::Ipv4(address) => vec![IpAddr::V4(address)],
        Host::Ipv6(address) => vec![IpAddr::V6(address)],
        Host::Domain(name) => resolve(name).map_err(ProbeError::Resolve)?,
    };
    let guarded = addresses
        .into_iter()
        .map(|address| guard_address(address, scope))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(guarded)
}


/// One hop: guard the target, send the request, then either follow a `Location` or finish.
pub fn hop(url: &Url, scope: &[IpNet], deadline: &Deadline, limits: &ProbeLimits, transports: &HttpTransports) -> Result<HopState, ProbeError> {
    let HttpTransports { resolve, fetch, clock } = *transports;
    let bad_target = || ProbeError::BadTarget { target: url.to_string() };
    let (host, port) = ["http", "https"]
        .contains(&url.scheme())
        .then(|| url.host().zip(url.port_or_known_default()))
        .flatten()
        .ok_or_else(bad_target)?;
    let left = remaining(clock, deadline)?;
    let address = guarded_addresses(host, scope, resolve)?.first().copied().ok_or(ProbeError::NoAddress)?;
    let request = HttpRequest {
        address,
        host: url[url::Position::BeforeHost..url::Position::AfterHost].to_string(),
        port,
        tls: url.scheme() == "https",
        path_and_query: url[url::Position::BeforePath..].to_string(),
    };
    let response = fetch(&request, left, limits.max_response_bytes).map_err(ProbeError::Transport)?;
    remaining(clock, deadline)?;
    let redirect = (FIRST_REDIRECT_STATUS..FIRST_ERROR_STATUS)
        .contains(&response.status)
        .then(|| response.location.clone())
        .flatten();
    match redirect {
        Some(location) => url.join(&location).map(HopState::Follow).map_err(ProbeError::BadRedirect),
        None => Ok(HopState::Done(response)),
    }
}


/// An HTTP(S) probe: every resolved address and every redirect target is guarded before a connection, redirects are capped, the deadline is hard.
pub fn http_probe(target: &str, scope: &[IpNet], limits: &ProbeLimits, transports: &HttpTransports) -> Result<ProbeOutcome, ProbeError> {
    let clock = transports.clock;
    let deadline = start_deadline(clock, limits.timeout);
    let first = Url::parse(target).map_err(|_| ProbeError::BadTarget { target: target.to_string() })?;
    let last = (0..=limits.max_redirects).try_fold(HopState::Follow(first), |state, _| match state {
        HopState::Follow(url) => hop(&url, scope, &deadline, limits, transports),
        HopState::Done(_) => Ok(state),
    })?;
    match last {
        HopState::Follow(_) => Err(ProbeError::TooManyRedirects { max: limits.max_redirects }),
        HopState::Done(response) => Ok(ProbeOutcome {
            status: Some(response.status),
            latency_ms: latency_ms(clock, &deadline),
            succeeded: (FIRST_SUCCESS_STATUS..FIRST_REDIRECT_STATUS).contains(&response.status),
            body_excerpt: escaped_excerpt(&response.body.into_iter().take(limits.max_response_bytes).collect::<Vec<u8>>()),
            certificate_chain: response.certificate_chain,
        }),
    }
}


/// A TCP probe: the connect only has to succeed within the remaining time.
pub fn tcp_probe(
    address: CheckedAddr,
    port: u16,
    limits: &ProbeLimits,
    connect: &Connect<'_>,
    clock: &Clock<'_>,
) -> Result<ProbeOutcome, ProbeError> {
    let deadline = start_deadline(clock, limits.timeout);
    let left = remaining(clock, &deadline)?;
    connect(probe_socket(address, port), left).map_err(ProbeError::Transport)?;
    remaining(clock, &deadline)?;
    Ok(ProbeOutcome {
        status: None,
        latency_ms: latency_ms(clock, &deadline),
        succeeded: true,
        body_excerpt: String::new(),
        certificate_chain: Vec::new(),
    })
}


/// A TLS probe: the handshake returns the presented chain (DER, leaf first), kept for the certificate inventory.
pub fn tls_probe(
    address: CheckedAddr,
    port: u16,
    server_name: &str,
    limits: &ProbeLimits,
    handshake: &Handshake<'_>,
    clock: &Clock<'_>,
) -> Result<ProbeOutcome, ProbeError> {
    let deadline = start_deadline(clock, limits.timeout);
    let left = remaining(clock, &deadline)?;
    let chain = handshake(probe_socket(address, port), server_name, left).map_err(ProbeError::Transport)?;
    remaining(clock, &deadline)?;
    let too_large = [
        chain.len() > MAX_CHAIN_CERTS,
        chain.iter().any(|certificate| certificate.len() > MAX_CERT_BYTES),
    ]
    .contains(&true);
    (!too_large).then_some(()).ok_or(ProbeError::ChainTooLarge {
        max_certs: MAX_CHAIN_CERTS,
        max_bytes: MAX_CERT_BYTES,
    })?;
    Ok(ProbeOutcome {
        status: None,
        latency_ms: latency_ms(clock, &deadline),
        succeeded: !chain.is_empty(),
        body_excerpt: String::new(),
        certificate_chain: chain,
    })
}


/// A DNS probe: succeeds when the name resolves; the answers (capped) are the excerpt. Nothing is connected to, so nothing is guarded.
pub fn dns_probe(name: &str, limits: &ProbeLimits, resolve: &Resolve<'_>, clock: &Clock<'_>) -> Result<ProbeOutcome, ProbeError> {
    let deadline = start_deadline(clock, limits.timeout);
    remaining(clock, &deadline)?;
    let answers: Vec<IpAddr> = resolve(name).map_err(ProbeError::Resolve)?.into_iter().take(MAX_DNS_ANSWERS).collect();
    remaining(clock, &deadline)?;
    let listing = answers.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(",");
    Ok(ProbeOutcome {
        status: None,
        latency_ms: latency_ms(clock, &deadline),
        succeeded: !answers.is_empty(),
        body_excerpt: escaped_excerpt(listing.as_bytes()),
        certificate_chain: Vec::new(),
    })
}
