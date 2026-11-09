use ipnet::IpNet;
use std::error::Error;
use std::io::{self, stdout, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use synthetic_checks::http::{fetch_with_roots, load_roots};
use synthetic_checks::probe::{http_probe, probe_limits, HttpTransports};


const TIMEOUT: Duration = Duration::from_secs(10);


const MAX_REDIRECTS: usize = 3;


const MAX_RESPONSE_BYTES: usize = 65_536;


const SCOPE_INDEX: usize = 1;


const CA_INDEX: usize = 2;


const USAGE: &str = "usage: http_check <url> [scope-cidr|-] [ca-file]";


fn literal_only(name: &str, _left: Duration, _cap: usize) -> io::Result<Vec<IpAddr>> {
    name.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .map(|address| vec![address])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let url = arguments.first().ok_or(USAGE)?;
    let scope: Vec<IpNet> = arguments
        .get(SCOPE_INDEX)
        .filter(|cidr| cidr.as_str() != "-")
        .map(|cidr| cidr.parse())
        .transpose()?
        .into_iter()
        .collect();
    let roots = load_roots(arguments.get(CA_INDEX).map(String::as_str))?;
    let fetch = fetch_with_roots(&roots);
    let started = Instant::now();
    let limits = probe_limits(TIMEOUT, MAX_RESPONSE_BYTES, MAX_REDIRECTS)?;
    let transports = HttpTransports {
        resolve: &literal_only,
        fetch: &fetch,
        clock: &|| started.elapsed(),
    };
    let outcome = http_probe(url, &scope, &limits, &transports);
    writeln!(stdout(), "{outcome:?}")?;
    Ok(())
}
