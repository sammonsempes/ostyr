use crate::error::{CheckError, GuardError, ProbeError};
use crate::load::validate_nat64_prefix;
use crate::model::{MAX_BODY_EXCERPT_BYTES, MAX_TIMEOUT_SECONDS};
use crate::target::{guard_address_nat64, probe_socket, CheckedAddr};
use crate::types::{Clock, Connect, Fetch, Handshake, Resolve};
use ipnet::{IpNet, Ipv6Net};
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use url::{Host, Url};


pub const MAX_REDIRECTS: usize = 5;


pub const MAX_RESPONSE_BYTES: usize = 1_048_576;


pub const MAX_CHAIN_CERTS: usize = 10;


pub const MAX_CERT_BYTES: usize = 16_384;


pub const MAX_DNS_ANSWERS: usize = 64;


pub const MAX_LOCATION_BYTES: usize = 2048;


pub const MAX_ERROR_TARGET_CHARS: usize = 128;


pub const UNPARSEABLE_TARGET: &str = "[unparseable target]";


pub const FIRST_SUCCESS_STATUS: u16 = 200;


pub const FIRST_REDIRECT_STATUS: u16 = 300;


pub const FIRST_ERROR_STATUS: u16 = 400;


/// Limits of one probe, only built by `probe_limits`: the hard deadline, the response cap and the redirect cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeLimits {
    timeout: Duration,
    max_response_bytes: usize,
    max_redirects: usize,
    nat64: Option<Ipv6Net>,
}


fn within_limit(field: &'static str, value: u64, max: u64) -> Result<(), CheckError> {
    (value <= max).then_some(()).ok_or(CheckError::OutOfRange { field, min: 0, max })
}


/// The only constructor of `ProbeLimits`: refuses a timeout above `MAX_TIMEOUT_SECONDS`, more than `MAX_RESPONSE_BYTES` or `MAX_REDIRECTS`.
pub fn probe_limits(timeout: Duration, max_response_bytes: usize, max_redirects: usize) -> Result<ProbeLimits, ProbeError> {
    within_limit(
        "timeout",
        timeout.as_secs().saturating_add(u64::from(timeout.subsec_nanos() > 0)),
        MAX_TIMEOUT_SECONDS,
    )?;
    within_limit("max_response_bytes", max_response_bytes as u64, MAX_RESPONSE_BYTES as u64)?;
    within_limit("max_redirects", max_redirects as u64, MAX_REDIRECTS as u64)?;
    Ok(ProbeLimits {
        timeout,
        max_response_bytes,
        max_redirects,
        nat64: None,
    })
}


/// The same limits with the site's declared NAT64 prefix, validated like the `nat64_prefix` check field; `None` clears it.
pub fn with_nat64_prefix(limits: ProbeLimits, nat64: Option<Ipv6Net>) -> Result<ProbeLimits, CheckError> {
    validate_nat64_prefix(nat64)?;
    Ok(ProbeLimits { nat64, ..limits })
}


/// A target for an error or a log: scheme and host only, so no userinfo, path or query (which may hold a secret) and a bounded length.
pub fn redacted_target(target: &str) -> String {
    Url::parse(target).map_or_else(
        |_| UNPARSEABLE_TARGET.to_string(),
        |url| {
            format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""))
                .chars()
                .take(MAX_ERROR_TARGET_CHARS)
                .collect()
        },
    )
}


/// What a probe records; the body is never kept in full and `certificate_chain` (DER, leaf first) is empty unless TLS was used; `certificate_verified` is `None` without TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub succeeded: bool,
    pub body_excerpt: String,
    pub certificate_chain: Vec<Vec<u8>>,
    pub certificate_verified: Option<bool>,
}


/// The caps handed to a fetch transport so it can stop before buffering: body bytes, certificates, bytes per certificate, `Location` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchCaps {
    pub body_bytes: usize,
    pub certificates: usize,
    pub certificate_bytes: usize,
    pub location_bytes: usize,
}


/// Refuses a chain of more than `MAX_CHAIN_CERTS` certificates or a certificate above `MAX_CERT_BYTES`.
pub fn check_chain(chain: &[Vec<u8>]) -> Result<(), ProbeError> {
    let too_large = [
        chain.len() > MAX_CHAIN_CERTS,
        chain.iter().any(|certificate| certificate.len() > MAX_CERT_BYTES),
    ]
    .contains(&true);
    (!too_large).then_some(()).ok_or(ProbeError::ChainTooLarge {
        max_certs: MAX_CHAIN_CERTS,
        max_bytes: MAX_CERT_BYTES,
    })
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
    pub certificate_verified: Option<bool>,
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
            if character.is_control() || matches!(character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
            {
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
pub fn guarded_addresses(
    host: Host<&str>,
    scope: &[IpNet],
    nat64: Option<Ipv6Net>,
    resolve: &Resolve<'_>,
    left: Duration,
) -> Result<Vec<CheckedAddr>, ProbeError> {
    validate_nat64_prefix(nat64).map_err(|error| ProbeError::Refused(GuardError::BadPrefix(error)))?;
    let addresses = match host {
        Host::Ipv4(address) => vec![IpAddr::V4(address)],
        Host::Ipv6(address) => vec![IpAddr::V6(address)],
        Host::Domain(name) => resolve(name, left, MAX_DNS_ANSWERS)
            .map_err(ProbeError::Resolve)?
            .into_iter()
            .take(MAX_DNS_ANSWERS)
            .collect(),
    };
    let guarded = addresses
        .into_iter()
        .map(|address| guard_address_nat64(address, scope, nat64))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(guarded)
}


/// One hop: guard the target, send the request, then either follow a `Location` or finish.
pub fn hop(url: &Url, scope: &[IpNet], deadline: &Deadline, limits: &ProbeLimits, transports: &HttpTransports) -> Result<HopState, ProbeError> {
    let HttpTransports { resolve, fetch, clock } = *transports;
    let bad_target = || ProbeError::BadTarget {
        target: redacted_target(url.as_str()),
    };
    let (host, port) = ["http", "https"]
        .contains(&url.scheme())
        .then(|| url.host().zip(url.port_or_known_default()))
        .flatten()
        .ok_or_else(bad_target)?;
    let address = guarded_addresses(host, scope, limits.nat64, resolve, remaining(clock, deadline)?)?
        .first()
        .copied()
        .ok_or(ProbeError::NoAddress)?;
    let left = remaining(clock, deadline)?;
    let request = HttpRequest {
        address,
        host: url[url::Position::BeforeHost..url::Position::AfterHost].to_string(),
        port,
        tls: url.scheme() == "https",
        path_and_query: url[url::Position::BeforePath..url::Position::AfterQuery].to_string(),
    };
    let caps = FetchCaps {
        body_bytes: limits.max_response_bytes,
        certificates: MAX_CHAIN_CERTS,
        certificate_bytes: MAX_CERT_BYTES,
        location_bytes: MAX_LOCATION_BYTES,
    };
    let response = fetch(&request, left, caps).map_err(ProbeError::Transport)?;
    remaining(clock, deadline)?;
    check_chain(&response.certificate_chain)?;
    let redirect = ((FIRST_REDIRECT_STATUS..FIRST_ERROR_STATUS).contains(&response.status) && response.certificate_verified != Some(false))
        .then(|| response.location.clone())
        .flatten();
    match redirect {
        Some(location) if location.len() > MAX_LOCATION_BYTES => Err(ProbeError::RedirectTooLong { max: MAX_LOCATION_BYTES }),
        Some(location) => url.join(&location).map(HopState::Follow).map_err(ProbeError::BadRedirect),
        None => Ok(HopState::Done(response)),
    }
}


/// An HTTP(S) probe: every resolved address and every redirect target is guarded before a connection, redirects are capped, the deadline is hard.
pub fn http_probe(target: &str, scope: &[IpNet], limits: &ProbeLimits, transports: &HttpTransports) -> Result<ProbeOutcome, ProbeError> {
    let clock = transports.clock;
    let deadline = start_deadline(clock, limits.timeout);
    let first = Url::parse(target).map_err(|_| ProbeError::BadTarget {
        target: redacted_target(target),
    })?;
    let last = (0..=limits.max_redirects)
        .scan(Some(first), |pending, _| {
            let url = pending.take()?;
            let result = hop(&url, scope, &deadline, limits, transports);
            *pending = match &result {
                Ok(HopState::Follow(next)) => Some(next.clone()),
                _ => None,
            };
            Some(result)
        })
        .last()
        .ok_or(ProbeError::NoAddress)??;
    match last {
        HopState::Follow(_) => Err(ProbeError::TooManyRedirects { max: limits.max_redirects }),
        HopState::Done(response) => Ok(ProbeOutcome {
            status: (response.certificate_verified != Some(false)).then_some(response.status),
            latency_ms: latency_ms(clock, &deadline),
            succeeded: (FIRST_SUCCESS_STATUS..FIRST_REDIRECT_STATUS).contains(&response.status) && response.certificate_verified != Some(false),
            body_excerpt: escaped_excerpt(&response.body.into_iter().take(limits.max_response_bytes).collect::<Vec<u8>>()),
            certificate_chain: response.certificate_chain,
            certificate_verified: response.certificate_verified,
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
    connect(probe_socket(address, port), left).map_err(|error| match error.kind() {
        io::ErrorKind::TimedOut => ProbeError::Timeout { limit: deadline.limit },
        _ => ProbeError::Transport(error),
    })?;
    remaining(clock, &deadline)?;
    Ok(ProbeOutcome {
        status: None,
        latency_ms: latency_ms(clock, &deadline),
        succeeded: true,
        body_excerpt: String::new(),
        certificate_chain: Vec::new(),
        certificate_verified: None,
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
    let chain = handshake(probe_socket(address, port), server_name, left, MAX_CHAIN_CERTS, MAX_CERT_BYTES).map_err(ProbeError::Transport)?;
    remaining(clock, &deadline)?;
    check_chain(&chain)?;
    Ok(ProbeOutcome {
        status: None,
        latency_ms: latency_ms(clock, &deadline),
        succeeded: !chain.is_empty(),
        body_excerpt: String::new(),
        certificate_chain: chain,
        certificate_verified: None,
    })
}


/// A DNS probe: succeeds when the name resolves; the answers (capped) are the excerpt. Nothing is connected to, so nothing is guarded.
pub fn dns_probe(name: &str, limits: &ProbeLimits, resolve: &Resolve<'_>, clock: &Clock<'_>) -> Result<ProbeOutcome, ProbeError> {
    let deadline = start_deadline(clock, limits.timeout);
    let answers: Vec<IpAddr> = resolve(name, remaining(clock, &deadline)?, MAX_DNS_ANSWERS)
        .map_err(ProbeError::Resolve)?
        .into_iter()
        .take(MAX_DNS_ANSWERS)
        .collect();
    remaining(clock, &deadline)?;
    let listing = answers.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(",");
    Ok(ProbeOutcome {
        status: None,
        latency_ms: latency_ms(clock, &deadline),
        succeeded: !answers.is_empty(),
        body_excerpt: escaped_excerpt(listing.as_bytes()),
        certificate_chain: Vec::new(),
        certificate_verified: None,
    })
}
