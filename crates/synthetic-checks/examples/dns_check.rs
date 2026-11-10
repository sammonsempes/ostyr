use ipnet::{IpNet, Ipv6Net};
use std::error::Error;
use std::io::{stdout, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use synthetic_checks::dns::dns_resolve;
use synthetic_checks::probe::{dns_probe, guarded_addresses, probe_limits};
use url::Host;


const TIMEOUT: Duration = Duration::from_secs(5);


const USAGE: &str = "usage: dns_check <name> [nameserver ip:port] [guard: scope CIDR or - [NAT64 prefix]]";


const NAMESERVER_INDEX: usize = 1;


const SCOPE_INDEX: usize = 2;


const NAT64_INDEX: usize = 3;


const MAX_ANSWERS: usize = 64;


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let name = arguments.first().ok_or(USAGE)?;
    let nameserver: Option<SocketAddr> = arguments.get(NAMESERVER_INDEX).map(|text| text.parse()).transpose()?;
    let limits = probe_limits(TIMEOUT, 1, 0)?;
    let started = Instant::now();
    let outcome = dns_probe(name, &limits, &|asked, left, cap| dns_resolve(nameserver, asked, left, cap), &|| {
        started.elapsed()
    });
    writeln!(stdout(), "{outcome:?}")?;
    let guarded = arguments.get(SCOPE_INDEX).map(|text| -> Result<_, Box<dyn Error>> {
        let scope: Vec<IpNet> = (text != "-").then(|| text.parse()).transpose()?.into_iter().collect();
        let nat64: Option<Ipv6Net> = arguments.get(NAT64_INDEX).map(|prefix| prefix.parse()).transpose()?;
        let resolve = |asked: &str, left: Duration, cap: usize| dns_resolve(nameserver, asked, left, cap.min(MAX_ANSWERS));
        Ok(guarded_addresses(Host::Domain(name.as_str()), &scope, nat64, &resolve, TIMEOUT))
    });
    guarded
        .transpose()?
        .iter()
        .try_for_each(|verdict| writeln!(stdout(), "guarded: {verdict:?}"))?;
    Ok(())
}
