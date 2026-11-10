use std::error::Error;
use std::io::{stdout, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use synthetic_checks::dns::dns_resolve;
use synthetic_checks::probe::{dns_probe, probe_limits};


const TIMEOUT: Duration = Duration::from_secs(5);


const USAGE: &str = "usage: dns_check <name> [nameserver ip:port]";


const NAMESERVER_INDEX: usize = 1;


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
    Ok(())
}
