#[path = "common/types.rs"]
mod types;


use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use synthetic_checks::dns::dns_resolve;
use synthetic_checks::error::ProbeError;
use synthetic_checks::probe::{dns_probe, guarded_addresses, probe_limits};
use types::TestResult;
use url::Host;


const LEFT: Duration = Duration::from_secs(10);


const SHORT: Duration = Duration::from_millis(100);


const CAP: usize = 64;


const SMALL_CAP: usize = 2;


const ID_BYTES: usize = 2;


const TYPE_CLASS_BYTES: usize = 4;


const MANY: [&str; 5] = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"];


const MAX_QUERIES: usize = 64;


const HEADER_BYTES: usize = 12;


const TYPE_A: u16 = 1;


const TYPE_AAAA: u16 = 28;


const NXDOMAIN: u8 = 3;


const REPLY_FLAGS: u8 = 0x81;


const RECURSION_AVAILABLE: u8 = 0x80;


const NAME_POINTER: [u8; 2] = [0xc0, 0x0c];


const TTL: [u8; 4] = [0, 0, 0, 60];


const CLASS_IN: [u8; 2] = [0, 1];


const PACKET_BYTES: usize = 512;


const PROBE_TIMEOUT_SECONDS: u64 = 5;


#[derive(Clone)]
enum Mode {
    Answers(Vec<IpAddr>),
    NxDomain,
    Silent,
}


struct Stub {
    address: SocketAddr,
    stop: UdpSocket,
    worker: JoinHandle<()>,
}


fn record(answer: &IpAddr) -> Result<Vec<u8>, std::num::TryFromIntError> {
    let (kind, data) = match answer {
        IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
        IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
    };
    let length = u16::try_from(data.len())?;
    Ok([
        NAME_POINTER.as_slice(),
        &kind.to_be_bytes(),
        &CLASS_IN,
        &TTL,
        &length.to_be_bytes(),
        &data,
    ]
    .concat())
}


fn answer_section(answers: &[&IpAddr]) -> Result<(u16, Vec<u8>), std::num::TryFromIntError> {
    let count = u16::try_from(answers.len())?;
    let records = answers.iter().copied().map(record).collect::<Result<Vec<_>, _>>()?.concat();
    Ok((count, records))
}


fn reply(query: &[u8], mode: &Mode) -> Option<Vec<u8>> {
    let identifier = query.get(..ID_BYTES)?;
    let body = query.get(HEADER_BYTES..)?;
    let name_length = body.iter().position(|byte| *byte == 0)?;
    let question = body.get(..name_length + 1 + TYPE_CLASS_BYTES)?;
    let kind = u16::from_be_bytes([*question.get(name_length + 1)?, *question.get(name_length + 1 + 1)?]);
    let answers: Vec<&IpAddr> = match mode {
        Mode::Answers(all) => all
            .iter()
            .filter(|answer| (kind == TYPE_A) == answer.is_ipv4() && (kind == TYPE_A || kind == TYPE_AAAA))
            .collect(),
        Mode::NxDomain | Mode::Silent => Vec::new(),
    };
    let rcode = if matches!(mode, Mode::NxDomain) { NXDOMAIN } else { 0 };
    let (count, records) = answer_section(&answers)
        .map_err(|error| tracing::warn!(%error, "stub answer section failed"))
        .ok()?;
    let header = [
        identifier,
        &[REPLY_FLAGS, RECURSION_AVAILABLE | rcode, 0, 1],
        &count.to_be_bytes(),
        &[0, 0, 0, 0],
    ]
    .concat();
    Some([header, question.to_vec(), records].concat())
}


fn serve(mode: Mode) -> Result<Stub, std::io::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let address = socket.local_addr()?;
    let stop = UdpSocket::bind("127.0.0.1:0")?;
    let worker = spawn(move || {
        let mut buffer = [0u8; PACKET_BYTES];
        (0..MAX_QUERIES)
            .map(|_| {
                socket
                    .recv_from(&mut buffer)
                    .ok()
                    .map(|(length, peer)| (buffer.get(..length).map(<[u8]>::to_vec), peer))
            })
            .take_while(|received| {
                received
                    .as_ref()
                    .is_some_and(|(packet, _)| packet.as_ref().is_some_and(|bytes| !bytes.is_empty()))
            })
            .flatten()
            .filter(|_| !matches!(mode, Mode::Silent))
            .filter_map(|(packet, peer)| packet.and_then(|bytes| reply(&bytes, &mode)).map(|bytes| (bytes, peer)))
            .for_each(|(bytes, peer)| {
                if let Err(error) = socket.send_to(&bytes, peer) {
                    tracing::warn!(%error, "stub reply failed");
                }
            });
    });
    Ok(Stub { address, stop, worker })
}


fn finish(stub: Stub) -> TestResult {
    stub.stop.send_to(&[], stub.address)?;
    stub.worker.join().map_err(|_| "stub thread failed")?;
    Ok(())
}


#[test]
fn a_and_aaaa_answers_come_back() -> TestResult {
    let v4 = IpAddr::V4("192.0.2.1".parse::<Ipv4Addr>()?);
    let v6 = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>()?);
    let stub = serve(Mode::Answers(vec![v4, v6]))?;
    let answers = dns_resolve(Some(stub.address), "check.example", LEFT, CAP)?;
    finish(stub)?;
    assert!(answers.contains(&v4));
    assert!(answers.contains(&v6));
    Ok(())
}


#[test]
fn nxdomain_is_an_error() -> TestResult {
    let stub = serve(Mode::NxDomain)?;
    let outcome = dns_resolve(Some(stub.address), "missing.example", LEFT, CAP);
    finish(stub)?;
    assert!(outcome.is_err());
    Ok(())
}


#[test]
fn answers_above_the_cap_are_cut() -> TestResult {
    let many: Vec<IpAddr> = MANY.iter().map(|text| text.parse()).collect::<Result<_, _>>()?;
    let stub = serve(Mode::Answers(many))?;
    let answers = dns_resolve(Some(stub.address), "many.example", LEFT, SMALL_CAP)?;
    finish(stub)?;
    assert_eq!(answers.len(), SMALL_CAP);
    Ok(())
}


#[test]
fn a_silent_server_times_out_within_the_time_left() -> TestResult {
    let stub = serve(Mode::Silent)?;
    let outcome = dns_resolve(Some(stub.address), "silent.example", SHORT, CAP);
    finish(stub)?;
    assert!(outcome.is_err());
    Ok(())
}


#[test]
fn a_dns64_answer_is_passed_back_unfiltered() -> TestResult {
    let synthesised = IpAddr::V6("64:ff9b::c0a8:1".parse::<Ipv6Addr>()?);
    let stub = serve(Mode::Answers(vec![synthesised]))?;
    let answers = dns_resolve(Some(stub.address), "dns64.example", LEFT, CAP)?;
    finish(stub)?;
    assert_eq!(answers, vec![synthesised]);
    Ok(())
}


fn refused_through_the_guard(answer: &str, scope: &[ipnet::IpNet]) -> Result<bool, Box<dyn std::error::Error>> {
    let synthesised = IpAddr::V6(answer.parse::<Ipv6Addr>()?);
    let stub = serve(Mode::Answers(vec![synthesised]))?;
    let resolve = |name: &str, left: Duration, cap: usize| dns_resolve(Some(stub.address), name, left, cap);
    let outcome = guarded_addresses(Host::Domain("synthesised.example"), scope, None, &resolve, LEFT);
    finish(stub)?;
    Ok(matches!(outcome, Err(ProbeError::Refused(_))))
}


#[test]
fn a_teredo_answer_is_refused_by_the_guard() -> TestResult {
    assert!(refused_through_the_guard("2001:0:c000:201::80ff:fffe", &[])?);
    assert!(refused_through_the_guard("2001:0:a9fe:a9fe::80ff:fffe", &["2001::/32".parse()?])?);
    assert!(refused_through_the_guard("2001:0:c000:201::5601:5601", &["2001::/32".parse()?])?);
    Ok(())
}


#[test]
fn a_network_specific_nat64_answer_is_refused_by_the_guard() -> TestResult {
    assert!(refused_through_the_guard("2001:db8:64::a9fe:a9fe", &[])?);
    assert!(refused_through_the_guard("2001:db8:64::a9fe:a9fe", &["2001:db8::/32".parse()?])?);
    assert!(!refused_through_the_guard("2606:4700::6810:84e5", &[])?);
    Ok(())
}


#[test]
fn the_system_configuration_is_used_without_a_nameserver() -> TestResult {
    let outcome = dns_resolve(None, "system.invalid", SHORT, CAP);
    assert!(outcome.iter().all(|answers| answers.len() <= CAP));
    Ok(())
}


#[test]
fn an_invalid_name_is_an_error() -> TestResult {
    let outcome = dns_resolve(Some("127.0.0.1:9".parse()?), &"a".repeat(PACKET_BYTES), SHORT, CAP);
    assert!(outcome.is_err());
    Ok(())
}


#[test]
fn the_dns_probe_runs_over_the_real_transport() -> TestResult {
    let v4 = IpAddr::V4("192.0.2.7".parse::<Ipv4Addr>()?);
    let stub = serve(Mode::Answers(vec![v4]))?;
    let limits = probe_limits(Duration::from_secs(PROBE_TIMEOUT_SECONDS), 1, 0)?;
    let address = stub.address;
    let outcome = dns_probe(
        "probe.example",
        &limits,
        &|name, left, cap| dns_resolve(Some(address), name, left, cap),
        &|| Duration::ZERO,
    )?;
    finish(stub)?;
    assert!(outcome.succeeded);
    assert!(outcome.body_excerpt.contains("192.0.2.7"));
    Ok(())
}
