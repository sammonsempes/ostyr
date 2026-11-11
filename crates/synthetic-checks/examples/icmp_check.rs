use ipnet::IpNet;
use std::error::Error;
use std::io::{stdout, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use synthetic_checks::dns::dns_resolve;
use synthetic_checks::probe::{guarded_addresses, icmp_probe, probe_limits};
use synthetic_checks::transport::icmp_echo;
use url::Host;


const USAGE: &str = "usage: icmp_check <ip or name> <timeout-ms> [scope-cidr]";


const SCOPE_INDEX: usize = 2;


const MAX_ANSWERS: usize = 64;


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (target, timeout_ms) = arguments.first().zip(arguments.get(1)).ok_or(USAGE)?;
    let timeout = Duration::from_millis(timeout_ms.parse()?);
    let scope: Vec<IpNet> = arguments.get(SCOPE_INDEX).map(|cidr| cidr.parse()).transpose()?.into_iter().collect();
    let host = target.parse::<IpAddr>().map_or(Host::Domain(target.as_str()), |address| match address {
        IpAddr::V4(v4) => Host::Ipv4(v4),
        IpAddr::V6(v6) => Host::Ipv6(v6),
    });
    let resolve = |name: &str, left: Duration, cap: usize| dns_resolve(None, name, left, cap.min(MAX_ANSWERS));
    let limits = probe_limits(timeout, 1, 0)?;
    let started = Instant::now();
    let guarded = guarded_addresses(host, &scope, None, &resolve, timeout);
    let report = match guarded {
        Ok(addresses) => addresses
            .into_iter()
            .map(|address| format!("{:?}", icmp_probe(address, &limits, &icmp_echo, &|| started.elapsed())))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(refused) => format!("refused before any packet: {refused}"),
    };
    writeln!(stdout(), "{report}")?;
    Ok(())
}
