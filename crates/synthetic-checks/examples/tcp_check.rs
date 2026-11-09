use ipnet::IpNet;
use std::error::Error;
use std::io::{stdout, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use synthetic_checks::probe::{probe_limits, tcp_probe};
use synthetic_checks::target::guard_address;
use synthetic_checks::transport::tcp_connect;


const TIMEOUT: Duration = Duration::from_secs(5);


const SCOPE_INDEX: usize = 2;


const USAGE: &str = "usage: tcp_check <ip> <port> [scope-cidr]";


fn check(address: &str, port: &str, scope: &[IpNet]) -> Result<String, Box<dyn Error>> {
    let report = match guard_address(address.parse::<IpAddr>()?, scope) {
        Ok(checked) => {
            let limits = probe_limits(TIMEOUT, 1, 0)?;
            let started = Instant::now();
            format!("{:?}", tcp_probe(checked, port.parse()?, &limits, &tcp_connect, &|| started.elapsed()))
        }
        Err(refused) => format!("refused before connecting: {refused}"),
    };
    Ok(report)
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (address, port) = arguments.first().zip(arguments.get(1)).ok_or(USAGE)?;
    let scope: Vec<IpNet> = arguments.get(SCOPE_INDEX).map(|cidr| cidr.parse()).transpose()?.into_iter().collect();
    writeln!(stdout(), "{}", check(address, port, &scope)?)?;
    Ok(())
}
