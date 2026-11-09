#[path = "common/types.rs"]
mod types;


use std::cell::{Cell, RefCell};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use synthetic_checks::error::{GuardError, ProbeError};
use synthetic_checks::model::{MAX_BODY_EXCERPT_BYTES, MAX_TIMEOUT_SECONDS};
use synthetic_checks::probe::{
    dns_probe, escaped_excerpt, http_probe, probe_limits, redacted_target, tcp_probe, tls_probe, FetchCaps, HttpRequest, HttpResponse,
    HttpTransports, ProbeLimits, MAX_CERT_BYTES, MAX_CHAIN_CERTS, MAX_DNS_ANSWERS, MAX_ERROR_TARGET_CHARS, MAX_LOCATION_BYTES, MAX_REDIRECTS,
    MAX_RESPONSE_BYTES, UNPARSEABLE_TARGET,
};
use synthetic_checks::target::{guard_address, CheckedAddr};
use synthetic_checks::types::{Clock, Fetch, Resolve};
use types::TestResult;


const TIMEOUT_SECONDS: u64 = 10;


const SLOW_STEP_SECONDS: u64 = 11;


const RESOLVE_STEP_SECONDS: u64 = 9;


const LATENCY_STEP_MS: u64 = 25;


const SMALL_CAP: usize = 4;


const OK: u16 = 200;


const FOUND: u16 = 302;


const BAD: u16 = 500;


const PORT: u16 = 8443;


const HTTPS_PORT: u16 = 443;


const SECOND_CERT_BYTE: u8 = 3;


const FIRST_CERT_BYTES: [u8; 2] = [1, SECOND_CERT_BYTE - 1];


const INVALID_UTF8_BYTE: u8 = 0xff;


const TWO_REDIRECTS: usize = 2;


fn limits(max_redirects: usize) -> Result<ProbeLimits, ProbeError> {
    probe_limits(Duration::from_secs(TIMEOUT_SECONDS), SMALL_CAP, max_redirects)
}


fn zero_timeout() -> Result<ProbeLimits, ProbeError> {
    probe_limits(Duration::ZERO, SMALL_CAP, 1)
}


fn response(status: u16, location: Option<&str>, body: &[u8]) -> HttpResponse {
    HttpResponse {
        status,
        location: location.map(str::to_string),
        body: body.to_vec(),
        certificate_chain: vec![vec![1]],
    }
}


fn public(text: &str) -> Result<CheckedAddr, Box<dyn std::error::Error>> {
    Ok(guard_address(text.parse()?, &[])?)
}


fn resolver(answers: &[&str]) -> impl Fn(&str, Duration, usize) -> io::Result<Vec<IpAddr>> {
    let parsed: Vec<IpAddr> = answers.iter().filter_map(|text| text.parse().ok()).collect();
    move |_, _, _| Ok(parsed.clone())
}


fn bundle<'a>(resolve: &'a Resolve<'a>, fetch: &'a Fetch<'a>, clock: &'a Clock<'a>) -> HttpTransports<'a> {
    HttpTransports { resolve, fetch, clock }
}


fn fixed_clock() -> Duration {
    Duration::ZERO
}


#[test]
fn http_success_records_status_latency_excerpt_and_chain() -> TestResult {
    let now = Cell::new(0);
    let clock = || Duration::from_millis(now.get());
    let seen = RefCell::new(Vec::new());
    let fetch = |request: &HttpRequest, left: Duration, cap: FetchCaps| {
        now.set(now.get() + LATENCY_STEP_MS);
        seen.borrow_mut().push((request.clone(), left, cap));
        Ok(response(OK, None, b"a\x1b[0mbcdefgh"))
    };
    let outcome = http_probe(
        "https://example.org/p?q=1#frag",
        &[],
        &limits(1)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &clock),
    )?;
    assert_eq!(outcome.status, Some(OK));
    assert!(outcome.succeeded);
    assert_eq!(outcome.latency_ms, LATENCY_STEP_MS);
    assert_eq!(outcome.body_excerpt, "a\\u{1b}[0");
    assert_eq!(outcome.certificate_chain, vec![vec![1]]);
    let calls = seen.borrow();
    let (request, left, cap) = calls.first().ok_or("no call")?;
    assert_eq!(request.address, public("93.184.216.34")?);
    assert_eq!((request.host.as_str(), request.port, request.tls), ("example.org", HTTPS_PORT, true));
    assert_eq!(request.path_and_query, "/p?q=1");
    assert_eq!(*left, Duration::from_secs(TIMEOUT_SECONDS));
    let expected = FetchCaps {
        body_bytes: SMALL_CAP,
        certificates: MAX_CHAIN_CERTS,
        certificate_bytes: MAX_CERT_BYTES,
        location_bytes: MAX_LOCATION_BYTES,
    };
    assert_eq!(*cap, expected);
    Ok(())
}


#[test]
fn http_error_status_and_plain_http() -> TestResult {
    let fetch = |request: &HttpRequest, _: Duration, _: FetchCaps| {
        assert!(!request.tls);
        Ok(response(BAD, None, b""))
    };
    let outcome = http_probe(
        "http://93.184.216.34:81/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&[]), &fetch, &fixed_clock),
    )?;
    assert!(!outcome.succeeded);
    assert_eq!(outcome.status, Some(BAD));
    Ok(())
}


#[test]
fn redirect_without_location_is_final() -> TestResult {
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(FOUND, None, b""));
    let outcome = http_probe(
        "https://[2606:4700::1111]/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&[]), &fetch, &fixed_clock),
    )?;
    assert_eq!(outcome.status, Some(FOUND));
    assert!(!outcome.succeeded);
    Ok(())
}


#[test]
fn relative_redirect_is_followed_and_guarded_again() -> TestResult {
    let hits = Cell::new(0);
    let fetch = |request: &HttpRequest, _: Duration, _: FetchCaps| {
        hits.set(hits.get() + 1);
        Ok(if request.path_and_query == "/" {
            response(FOUND, Some("/next"), b"")
        } else {
            response(OK, None, b"ok")
        })
    };
    let outcome = http_probe(
        "https://example.org/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &fixed_clock),
    )?;
    assert_eq!(hits.get(), TWO_REDIRECTS);
    assert_eq!(outcome.body_excerpt, "ok");
    Ok(())
}


#[test]
fn redirect_to_metadata_is_refused_before_connecting() -> TestResult {
    let hits = Cell::new(0);
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| {
        hits.set(hits.get() + 1);
        Ok(response(FOUND, Some("http://169.254.169.254/latest/meta-data"), b""))
    };
    let scope = ["169.254.0.0/16".parse()?];
    let error = http_probe(
        "https://example.org/",
        &scope,
        &limits(MAX_REDIRECTS)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &fixed_clock),
    )
    .err()
    .ok_or("expected a refusal")?;
    assert!(matches!(error, ProbeError::Refused(GuardError::Refused { .. })));
    assert_eq!(hits.get(), 1);
    Ok(())
}


#[test]
fn redirect_to_a_name_resolving_to_a_private_address_is_refused() -> TestResult {
    let resolve = |name: &str, _: Duration, _: usize| -> io::Result<Vec<IpAddr>> {
        let text = if name == "example.org" { "93.184.216.34" } else { "10.0.0.5" };
        text.parse().map(|address| vec![address]).map_err(io::Error::other)
    };
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(FOUND, Some("https://internal.example/"), b""));
    let error = http_probe(
        "https://example.org/",
        &[],
        &limits(MAX_REDIRECTS)?,
        &bundle(&resolve, &fetch, &fixed_clock),
    )
    .err()
    .ok_or("expected a refusal")?;
    assert!(matches!(error, ProbeError::Refused(_)));
    Ok(())
}


#[test]
fn one_refused_address_among_several_refuses_the_host() -> TestResult {
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(OK, None, b""));
    let error = http_probe(
        "https://example.org/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&["93.184.216.34", "127.0.0.1"]), &fetch, &fixed_clock),
    )
    .err()
    .ok_or("expected a refusal")?;
    assert!(matches!(error, ProbeError::Refused(_)));
    Ok(())
}


#[test]
fn redirects_are_capped() -> TestResult {
    let hits = Cell::new(0);
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| {
        hits.set(hits.get() + 1);
        Ok(response(FOUND, Some("/again"), b""))
    };
    let error = http_probe(
        "https://example.org/",
        &[],
        &limits(TWO_REDIRECTS)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &fixed_clock),
    )
    .err()
    .ok_or("expected an error")?;
    assert!(matches!(error, ProbeError::TooManyRedirects { max: TWO_REDIRECTS }));
    assert_eq!(hits.get(), TWO_REDIRECTS + 1);
    Ok(())
}


#[test]
fn bad_targets_and_redirects_are_errors() -> TestResult {
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(FOUND, Some("http://[bad"), b""));
    let resolve = resolver(&["93.184.216.34"]);
    let transports = bundle(&resolve, &fetch, &fixed_clock);
    let cases = ["not a url", "ftp://example.org/", "mailto:a@b.c"];
    cases.iter().try_for_each(|target| -> TestResult {
        let error = http_probe(target, &[], &limits(1)?, &transports).err().ok_or("expected an error")?;
        assert!(matches!(error, ProbeError::BadTarget { .. }), "{target}");
        Ok(())
    })?;
    let error_2 = http_probe("https://example.org/", &[], &limits(1)?, &transports)
        .err()
        .ok_or("expected an error_2")?;
    assert!(matches!(error_2, ProbeError::BadRedirect(_)));
    Ok(())
}


#[test]
fn resolution_and_transport_failures_keep_their_cause() -> TestResult {
    let failing_resolve = |_: &str, _: Duration, _: usize| -> io::Result<Vec<IpAddr>> { Err(io::Error::other("no dns")) };
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Err(io::Error::other("reset"));
    let error = http_probe("https://example.org/", &[], &limits(1)?, &bundle(&failing_resolve, &fetch, &fixed_clock))
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(error, ProbeError::Resolve(_)));
    let error_2 = http_probe(
        "https://example.org/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &fixed_clock),
    )
    .err()
    .ok_or("expected an error_2")?;
    assert!(matches!(error_2, ProbeError::Transport(_)));
    let error_3 = http_probe("https://example.org/", &[], &limits(1)?, &bundle(&resolver(&[]), &fetch, &fixed_clock))
        .err()
        .ok_or("expected an error_3")?;
    assert!(matches!(error_3, ProbeError::NoAddress));
    Ok(())
}


#[test]
fn a_slow_transport_hits_the_deadline_on_a_paused_clock() -> TestResult {
    let now = Cell::new(0);
    let clock = || Duration::from_secs(now.get());
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| {
        now.set(SLOW_STEP_SECONDS);
        Ok(response(OK, None, b""))
    };
    let error = http_probe(
        "https://example.org/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &clock),
    )
    .err()
    .ok_or("expected a timeout")?;
    assert!(matches!(error, ProbeError::Timeout { .. }));
    now.set(SLOW_STEP_SECONDS);
    let untouched = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(OK, None, b""));
    let outcome = http_probe(
        "https://example.org/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&["93.184.216.34"]), &untouched, &clock),
    )?;
    assert!(outcome.succeeded);
    Ok(())
}


#[test]
fn a_zero_timeout_fails_before_any_connection() -> TestResult {
    let zero = zero_timeout()?;
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(OK, None, b""));
    let error = http_probe(
        "https://example.org/",
        &[],
        &zero,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &fixed_clock),
    )
    .err()
    .ok_or("expected a timeout")?;
    assert!(matches!(error, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn tcp_probe_connects_to_the_checked_socket() -> TestResult {
    let seen = RefCell::new(None);
    let connect = |socket: SocketAddr, _: Duration| {
        *seen.borrow_mut() = Some(socket);
        Ok(())
    };
    let outcome = tcp_probe(public("93.184.216.34")?, PORT, &limits(1)?, &connect, &fixed_clock)?;
    assert!(outcome.succeeded);
    assert_eq!(*seen.borrow(), Some("93.184.216.34:8443".parse()?));
    Ok(())
}


#[test]
fn tcp_probe_failure_and_deadline() -> TestResult {
    let refused = |_: SocketAddr, _: Duration| Err(io::Error::other("refused"));
    let error = tcp_probe(public("93.184.216.34")?, PORT, &limits(1)?, &refused, &fixed_clock)
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(error, ProbeError::Transport(_)));
    let now = Cell::new(0);
    let clock = || Duration::from_secs(now.get());
    let slow = |_: SocketAddr, _: Duration| {
        now.set(SLOW_STEP_SECONDS);
        Ok(())
    };
    let error_2 = tcp_probe(public("93.184.216.34")?, PORT, &limits(1)?, &slow, &clock)
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error_2, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn tcp_probe_maps_a_timed_out_connect_to_a_timeout() -> TestResult {
    let timed_out = |_: SocketAddr, _: Duration| Err(io::Error::from(io::ErrorKind::TimedOut));
    let error = tcp_probe(public("93.184.216.34")?, PORT, &limits(1)?, &timed_out, &fixed_clock)
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn tls_probe_returns_the_chain() -> TestResult {
    let names = RefCell::new(String::new());
    let handshake = |_: SocketAddr, name: &str, _: Duration, _: usize, _: usize| {
        names.borrow_mut().push_str(name);
        Ok(vec![FIRST_CERT_BYTES.to_vec(), vec![SECOND_CERT_BYTE]])
    };
    let outcome = tls_probe(public("93.184.216.34")?, PORT, "example.org", &limits(1)?, &handshake, &fixed_clock)?;
    assert!(outcome.succeeded);
    assert_eq!(outcome.certificate_chain, vec![FIRST_CERT_BYTES.to_vec(), vec![SECOND_CERT_BYTE]]);
    assert_eq!(names.borrow().as_str(), "example.org");
    let empty = |_: SocketAddr, _: &str, _: Duration, _: usize, _: usize| Ok(Vec::new());
    let outcome_2 = tls_probe(public("93.184.216.34")?, PORT, "example.org", &limits(1)?, &empty, &fixed_clock)?;
    assert!(!outcome_2.succeeded);
    Ok(())
}


#[test]
fn tls_probe_bounds_the_chain_and_reports_failures() -> TestResult {
    let long = |_: SocketAddr, _: &str, _: Duration, _: usize, _: usize| Ok(vec![vec![0]; MAX_CHAIN_CERTS + 1]);
    let big = |_: SocketAddr, _: &str, _: Duration, _: usize, _: usize| Ok(vec![vec![0; MAX_CERT_BYTES + 1]]);
    let failing = |_: SocketAddr, _: &str, _: Duration, _: usize, _: usize| Err(io::Error::other("alert"));
    let address = public("93.184.216.34")?;
    let too_large = |error: Option<ProbeError>| matches!(error, Some(ProbeError::ChainTooLarge { .. }));
    assert!(too_large(tls_probe(address, PORT, "h", &limits(1)?, &long, &fixed_clock).err()));
    assert!(too_large(tls_probe(address, PORT, "h", &limits(1)?, &big, &fixed_clock).err()));
    let error = tls_probe(address, PORT, "h", &limits(1)?, &failing, &fixed_clock)
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(error, ProbeError::Transport(_)));
    let now = Cell::new(0);
    let clock = || Duration::from_secs(now.get());
    let slow = |_: SocketAddr, _: &str, _: Duration, _: usize, _: usize| {
        now.set(SLOW_STEP_SECONDS);
        Ok(Vec::new())
    };
    let error_2 = tls_probe(address, PORT, "h", &limits(1)?, &slow, &clock)
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error_2, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn dns_probe_lists_capped_answers() -> TestResult {
    let outcome = dns_probe("example.org", &limits(1)?, &resolver(&["93.184.216.34", "2606:4700::1111"]), &fixed_clock)?;
    assert!(outcome.succeeded);
    assert_eq!(outcome.body_excerpt, "93.184.216.34,2606:4700::1111");
    let many = vec!["93.184.216.34"; MAX_DNS_ANSWERS + 1];
    let outcome_2 = dns_probe("example.org", &limits(1)?, &resolver(&many), &fixed_clock)?;
    assert!(outcome_2.succeeded);
    assert!(outcome_2.body_excerpt.len() <= MAX_BODY_EXCERPT_BYTES);
    let outcome_3 = dns_probe("example.org", &limits(1)?, &resolver(&[]), &fixed_clock)?;
    assert!(!outcome_3.succeeded);
    Ok(())
}


#[test]
fn dns_probe_failure_and_deadline() -> TestResult {
    let failing = |_: &str, _: Duration, _: usize| -> io::Result<Vec<IpAddr>> { Err(io::Error::other("servfail")) };
    let error = dns_probe("example.org", &limits(1)?, &failing, &fixed_clock)
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(error, ProbeError::Resolve(_)));
    let now = Cell::new(0);
    let clock = || Duration::from_secs(now.get());
    let slow = |_: &str, _: Duration, _: usize| -> io::Result<Vec<IpAddr>> {
        now.set(SLOW_STEP_SECONDS);
        Ok(Vec::new())
    };
    let error_2 = dns_probe("example.org", &limits(1)?, &slow, &clock).err().ok_or("expected a timeout")?;
    assert!(matches!(error_2, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn escaped_excerpt_escapes_and_caps_after_escaping() -> TestResult {
    assert_eq!(escaped_excerpt(b"a\nb\x00"), "a\\nb\\u{0}");
    assert_eq!(escaped_excerpt(&vec![b'\n'; MAX_BODY_EXCERPT_BYTES]).len(), MAX_BODY_EXCERPT_BYTES);
    assert_eq!(escaped_excerpt(&[INVALID_UTF8_BYTE]), "\u{fffd}");
    assert_eq!(
        escaped_excerpt("a\u{202e}b\u{2066}c\u{2069}d\u{202a}".as_bytes()),
        "a\\u{202e}b\\u{2066}c\\u{2069}d\\u{202a}"
    );
    assert_eq!(
        escaped_excerpt("\u{2029}\u{202f}\u{2065}\u{206a}".as_bytes()),
        "\u{2029}\u{202f}\u{2065}\u{206a}"
    );
    Ok(())
}


#[test]
fn a_zero_timeout_fails_every_probe_kind_before_the_transport() -> TestResult {
    let zero = zero_timeout()?;
    let address = public("93.184.216.34")?;
    let connect = |_: SocketAddr, _: Duration| Ok(());
    let handshake = |_: SocketAddr, _: &str, _: Duration, _: usize, _: usize| Ok(Vec::new());
    let timed_out = |error: Option<ProbeError>| matches!(error, Some(ProbeError::Timeout { .. }));
    assert!(timed_out(tcp_probe(address, PORT, &zero, &connect, &fixed_clock).err()));
    assert!(timed_out(tls_probe(address, PORT, "h", &zero, &handshake, &fixed_clock).err()));
    assert!(timed_out(dns_probe("h", &zero, &resolver(&[]), &fixed_clock).err()));
    Ok(())
}


#[test]
fn resolution_time_is_deducted_from_the_budget() -> TestResult {
    let now = Cell::new(0);
    let clock = || Duration::from_secs(now.get());
    let lefts = RefCell::new(Vec::new());
    let slow_resolve = |_: &str, left: Duration, _: usize| -> io::Result<Vec<IpAddr>> {
        lefts.borrow_mut().push(left);
        now.set(RESOLVE_STEP_SECONDS);
        Ok(vec!["93.184.216.34".parse().map_err(io::Error::other)?])
    };
    let fetch = |_: &HttpRequest, left: Duration, _: FetchCaps| {
        lefts.borrow_mut().push(left);
        Ok(response(OK, None, b""))
    };
    http_probe("https://example.org/", &[], &limits(1)?, &bundle(&slow_resolve, &fetch, &clock))?;
    assert_eq!(
        *lefts.borrow(),
        vec![
            Duration::from_secs(TIMEOUT_SECONDS),
            Duration::from_secs(TIMEOUT_SECONDS - RESOLVE_STEP_SECONDS)
        ]
    );
    let late_resolve = |_: &str, _: Duration, _: usize| -> io::Result<Vec<IpAddr>> {
        now.set(SLOW_STEP_SECONDS);
        Ok(vec!["93.184.216.34".parse().map_err(io::Error::other)?])
    };
    now.set(0);
    let never = |_: &HttpRequest, _: Duration, _: FetchCaps| Err(io::Error::other("must not be called"));
    let error = http_probe("https://example.org/", &[], &limits(1)?, &bundle(&late_resolve, &never, &clock))
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error, ProbeError::Timeout { .. }));
    now.set(0);
    let error_2 = dns_probe("example.org", &limits(1)?, &late_resolve, &clock)
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error_2, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn resolvers_and_handshakes_receive_their_caps() -> TestResult {
    let caps = RefCell::new(Vec::new());
    let resolve = |_: &str, _: Duration, answers: usize| -> io::Result<Vec<IpAddr>> {
        caps.borrow_mut().push(answers);
        Ok(vec!["93.184.216.34".parse().map_err(io::Error::other)?; MAX_DNS_ANSWERS + 1])
    };
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(OK, None, b""));
    http_probe("https://example.org/", &[], &limits(1)?, &bundle(&resolve, &fetch, &fixed_clock))?;
    dns_probe("example.org", &limits(1)?, &resolve, &fixed_clock)?;
    assert_eq!(*caps.borrow(), vec![MAX_DNS_ANSWERS, MAX_DNS_ANSWERS]);
    let handshake = |_: SocketAddr, _: &str, _: Duration, certs: usize, bytes: usize| {
        caps.borrow_mut().extend([certs, bytes]);
        Ok(Vec::new())
    };
    tls_probe(public("93.184.216.34")?, PORT, "h", &limits(1)?, &handshake, &fixed_clock)?;
    assert_eq!(caps.borrow().get(TWO_REDIRECTS..), Some(&[MAX_CHAIN_CERTS, MAX_CERT_BYTES][..]));
    Ok(())
}


#[test]
fn limits_are_validated() -> TestResult {
    let second = Duration::from_secs(1);
    assert!(probe_limits(Duration::from_secs(MAX_TIMEOUT_SECONDS), MAX_RESPONSE_BYTES, MAX_REDIRECTS).is_ok());
    let refused = |error: Result<ProbeLimits, ProbeError>| matches!(error, Err(ProbeError::BadLimits(_)));
    assert!(refused(probe_limits(
        Duration::from_secs(MAX_TIMEOUT_SECONDS) + Duration::from_nanos(1),
        1,
        1
    )));
    assert!(refused(probe_limits(second, MAX_RESPONSE_BYTES + 1, 1)));
    assert!(refused(probe_limits(second, 1, MAX_REDIRECTS + 1)));
    assert!(refused(probe_limits(second, 1, usize::MAX)));
    Ok(())
}


#[test]
fn a_done_response_stops_the_redirect_loop() -> TestResult {
    let hits = Cell::new(0);
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| {
        hits.set(hits.get() + 1);
        Ok(response(OK, None, b""))
    };
    http_probe(
        "https://example.org/",
        &[],
        &limits(MAX_REDIRECTS)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &fixed_clock),
    )?;
    assert_eq!(hits.get(), 1);
    Ok(())
}


#[test]
fn an_oversized_location_is_refused_without_echo() -> TestResult {
    let long = "x".repeat(MAX_LOCATION_BYTES + 1);
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(FOUND, Some(&long), b""));
    let error = http_probe(
        "https://example.org/",
        &[],
        &limits(1)?,
        &bundle(&resolver(&["93.184.216.34"]), &fetch, &fixed_clock),
    )
    .err()
    .ok_or("expected an error")?;
    assert!(matches!(error, ProbeError::RedirectTooLong { max: MAX_LOCATION_BYTES }));
    assert!(!error.to_string().contains("xxx"));
    Ok(())
}


#[test]
fn errors_never_carry_userinfo_path_or_query() -> TestResult {
    let fetch = |_: &HttpRequest, _: Duration, _: FetchCaps| Ok(response(OK, None, b""));
    let resolve = resolver(&["93.184.216.34"]);
    let transports = bundle(&resolve, &fetch, &fixed_clock);
    let message = |target: &str| -> Result<String, Box<dyn std::error::Error>> {
        Ok(http_probe(target, &[], &limits(1)?, &transports)
            .err()
            .ok_or("expected an error")?
            .to_string())
    };
    let ftp = message("ftp://user:secret@example.org/path?token=abc")?;
    assert!(ftp.contains("ftp://example.org"));
    ["secret", "user", "token", "path"]
        .iter()
        .for_each(|word| assert!(!ftp.contains(word), "{word}"));
    let unparseable = message("http://us:secret@[bad")?;
    assert!(unparseable.contains(UNPARSEABLE_TARGET));
    assert!(!unparseable.contains("secret"));
    assert_eq!(redacted_target("mailto:a@b.c"), "mailto://");
    let long_host = format!("http://{}.example/", "a".repeat(MAX_ERROR_TARGET_CHARS + MAX_ERROR_TARGET_CHARS));
    assert_eq!(redacted_target(&long_host).chars().count(), MAX_ERROR_TARGET_CHARS);
    Ok(())
}


#[test]
fn an_oversized_https_chain_is_refused() -> TestResult {
    let resolve = resolver(&["93.184.216.34"]);
    let long = |_: &HttpRequest, _: Duration, _: FetchCaps| {
        let mut reply = response(OK, None, b"");
        reply.certificate_chain = vec![vec![0]; MAX_CHAIN_CERTS + 1];
        Ok(reply)
    };
    let big = |_: &HttpRequest, _: Duration, _: FetchCaps| {
        let mut reply = response(FOUND, Some("/next"), b"");
        reply.certificate_chain = vec![vec![0; MAX_CERT_BYTES + 1]];
        Ok(reply)
    };
    let too_large = |error: Option<ProbeError>| matches!(error, Some(ProbeError::ChainTooLarge { .. }));
    assert!(too_large(
        http_probe("https://example.org/", &[], &limits(1)?, &bundle(&resolve, &long, &fixed_clock)).err()
    ));
    assert!(too_large(
        http_probe("https://example.org/", &[], &limits(1)?, &bundle(&resolve, &big, &fixed_clock)).err()
    ));
    Ok(())
}
