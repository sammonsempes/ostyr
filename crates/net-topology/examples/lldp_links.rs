//! Usage: `lldp_links host <interfaces-report> <port-report-dir> <host> <now>` collects every port of a host from `<dir>/<port>.json`; or `lldp_links <report> <host> [now [stale_after [previous_report previous_now [port]]]]`. Prints the links of an `lldpcli -f json0` report, merged onto an earlier report, with staleness.
use net_topology::collect::collect_host;
use net_topology::limits::Limits;
use net_topology::links::{build_links, is_stale, merge_observations};
use net_topology::lldp::{parse_lldpd, parse_lldpd_port};
use net_topology::model::{Link, Skipped};
use net_topology::ports::parse_ports;
use net_topology::types::AnyError;
use std::fs::File;
use std::io::{stdout, Read, Write};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};


const NOW_ARGUMENT: usize = 2;


const STALE_ARGUMENT: usize = 3;


const PREVIOUS_ARGUMENT: usize = 4;


const PREVIOUS_NOW_ARGUMENT: usize = 5;


const PORT_ARGUMENT: usize = 6;


const TENANT: &str = "lab";


const DIR_ARGUMENT: usize = 2;


const HOST_ARGUMENT: usize = 3;


const HOST_NOW_ARGUMENT: usize = 4;


const HOST_MODE: &str = "host";


static PORT_DIR: OnceLock<PathBuf> = OnceLock::new();


fn run_from_dir(port: &str, cap: u64) -> std::io::Result<Vec<u8>> {
    let dir = PORT_DIR.get().ok_or_else(|| std::io::Error::other("no port directory"))?;
    let mut buffer = Vec::new();
    File::open(dir.join(format!("{port}.json")))?
        .take(cap.saturating_add(1))
        .read_to_end(&mut buffer)?;
    Ok(buffer)
}


fn host_mode(arguments: &[String]) -> Result<(), AnyError> {
    let interfaces = arguments.get(1).ok_or("missing interfaces report")?;
    let dir = arguments.get(DIR_ARGUMENT).ok_or("missing port report directory")?;
    let host = arguments.get(HOST_ARGUMENT).ok_or("missing host")?;
    let now = arguments.get(HOST_NOW_ARGUMENT).ok_or("missing now")?.parse::<i64>()?;
    PORT_DIR.set(PathBuf::from(dir)).map_err(|_| "port directory already set")?;
    let limits = Limits::default();
    let list = parse_ports(File::open(interfaces)?, &limits)?;
    let read = collect_host(host, &list.ports, now, &limits, run_from_dir)?;
    let links = build_links(TENANT, read.observations)?;
    let mut out = stdout();
    writeln!(
        out,
        "links {} ports_run {} failed {} skipped_budget {} refused_ports {}",
        links.len(),
        read.ports_run,
        read.failed_ports.len(),
        read.skipped_budget,
        read.refused_ports + list.refused_ports
    )?;
    read.failed_ports
        .iter()
        .try_for_each(|(port, failure)| writeln!(out, "failed {port:?} {failure:?}"))?;
    links.iter().try_for_each(|link| {
        writeln!(
            out,
            "link {:?} {:?} -> {:?} {:?}",
            link.local_host, link.local_port, link.remote_chassis, link.remote_port
        )
    })?;
    Ok(())
}


fn links_of(path: &str, host: &str, port: Option<&str>, now: i64, limits: &Limits) -> Result<(Vec<Link>, Skipped), AnyError> {
    let parsed = match port {
        Some(local_port) => parse_lldpd_port(File::open(path)?, host, local_port, now, limits)?,
        None => parse_lldpd(File::open(path)?, host, now, limits)?,
    };
    Ok((build_links(TENANT, parsed.observations)?, parsed.skipped))
}


fn main() -> Result<(), AnyError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) == Some(HOST_MODE) {
        host_mode(&arguments)
    } else {
        report_mode(&arguments)
    }
}


fn report_mode(arguments: &[String]) -> Result<(), AnyError> {
    let path = arguments.first().ok_or("missing report")?;
    let host = arguments.get(1).ok_or("missing host")?;
    let now = match arguments.get(NOW_ARGUMENT) {
        Some(text) => text.parse::<i64>()?,
        None => i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?,
    };
    let stale_after = arguments.get(STALE_ARGUMENT).map(|text| text.parse::<i64>()).transpose()?;
    let port = arguments.get(PORT_ARGUMENT).map(String::as_str);
    let limits = Limits::default();
    let (current, skipped) = links_of(path, host, port, now, &limits)?;
    let previous = match (arguments.get(PREVIOUS_ARGUMENT), arguments.get(PREVIOUS_NOW_ARGUMENT)) {
        (Some(previous_path), Some(previous_now)) => links_of(previous_path, host, port, previous_now.parse::<i64>()?, &limits)?.0,
        _ => Vec::new(),
    };
    let merged = merge_observations(previous, current, now, limits.max_links_per_host, limits.max_links_per_port)?;
    let mut out = stdout();
    writeln!(
        out,
        "links {} unparsable {} bad_field {} dropped_display {} control_bytes {} refused_new {}",
        merged.links.len(),
        skipped.unparsable,
        skipped.bad_field,
        skipped.dropped_display,
        skipped.control_bytes,
        merged.refused_new
    )?;
    merged.links.iter().try_for_each(|link| -> Result<(), AnyError> {
        let state = match stale_after {
            Some(seconds) if is_stale(link, now, seconds)? => "stale",
            Some(_) => "fresh",
            None => "unchecked",
        };
        writeln!(
            out,
            "link {:?} {:?} -> {:?} {:?} name={:?} first_seen={} last_seen={} {state}",
            link.local_host, link.local_port, link.remote_chassis, link.remote_port, link.remote_name, link.first_seen, link.last_seen
        )?;
        Ok(())
    })?;
    Ok(())
}
