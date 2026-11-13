//! Usage: `lldp_links <report> <host> [now [stale_after [previous_report previous_now]]]`. Prints the links of an `lldpcli -f json0` report, merged onto an earlier report, with staleness.
use net_topology::limits::Limits;
use net_topology::links::{build_links, is_stale, merge_observations};
use net_topology::lldp::parse_lldpd;
use net_topology::model::{Link, Skipped};
use net_topology::types::AnyError;
use std::fs::File;
use std::io::{stdout, Write};
use std::time::{SystemTime, UNIX_EPOCH};


const NOW_ARGUMENT: usize = 2;


const STALE_ARGUMENT: usize = 3;


const PREVIOUS_ARGUMENT: usize = 4;


const PREVIOUS_NOW_ARGUMENT: usize = 5;


const TENANT: &str = "lab";


fn links_of(path: &str, host: &str, now: i64, limits: &Limits) -> Result<(Vec<Link>, Skipped), AnyError> {
    let parsed = parse_lldpd(File::open(path)?, host, now, limits)?;
    Ok((build_links(TENANT, parsed.observations)?, parsed.skipped))
}


fn main() -> Result<(), AnyError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let path = arguments.first().ok_or("missing report")?;
    let host = arguments.get(1).ok_or("missing host")?;
    let now = match arguments.get(NOW_ARGUMENT) {
        Some(text) => text.parse::<i64>()?,
        None => i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?,
    };
    let stale_after = arguments.get(STALE_ARGUMENT).map(|text| text.parse::<i64>()).transpose()?;
    let limits = Limits::default();
    let (current, skipped) = links_of(path, host, now, &limits)?;
    let previous = match (arguments.get(PREVIOUS_ARGUMENT), arguments.get(PREVIOUS_NOW_ARGUMENT)) {
        (Some(previous_path), Some(previous_now)) => links_of(previous_path, host, previous_now.parse::<i64>()?, &limits)?.0,
        _ => Vec::new(),
    };
    let merged = merge_observations(previous, current, now, limits.max_links_per_host, limits.max_links_per_port)?;
    let mut out = stdout();
    writeln!(
        out,
        "links {} unparsable {} bad_field {} dropped_display {} refused_new {}",
        merged.links.len(),
        skipped.unparsable,
        skipped.bad_field,
        skipped.dropped_display,
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
