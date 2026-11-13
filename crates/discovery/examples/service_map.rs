use cmdb::model::{Asset, AssetKind, IdentityKey, Lifecycle};
use dhcp_kea::header::parse_header;
use dhcp_kea::row::convert_row;
use discovery::candidates::{candidates, known_devices};
use discovery::leases::lease_hints;
use discovery::map::{counters, edges, new_service_map, observe};
use discovery::model::ServiceMap;
use discovery::model::{LeaseLimits, ObserveLimits, TenantEvent};
use discovery::observe_cmdb::observations;
use discovery::scope::load_scope;
use site_collector::flow::parse_netflow_v5;
use site_collector::flow_model::{FlowBatch, FlowLimits, MAX_TEMPLATE_DATAGRAM_BYTES};
use site_collector::template_model::TemplateCache;
use site_collector::template_parse::{parse_ipfix, parse_netflow_v9};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};


const USAGE: &str =
    "usage: service_map <scope.yaml> <flow-datagram-file>... [--known <addresses-file>] [--leases <kea-leases4.csv> --inventory <id-mac-file>]";


const EXAMPLE_TENANT: &str = "example";


const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);


const BYTE_BITS: u32 = 8;


const NETFLOW_V9: u16 = 9;


const IPFIX: u16 = 10;


const MAX_LEASE_BYTES: u64 = 16_777_216;


const MAX_KNOWN_BYTES: u64 = 1_048_576;


fn read_capped(path: &str, max: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(u64::try_from(max)? + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}


fn parse(bytes: &[u8], cache: &mut TemplateCache) -> Result<FlowBatch, Box<dyn Error>> {
    let limits = FlowLimits::default();
    let version = bytes
        .first()
        .zip(bytes.get(1))
        .map_or(0, |(high, low)| (u16::from(*high) << BYTE_BITS) | u16::from(*low));
    let batch = match version {
        NETFLOW_V9 => parse_netflow_v9(bytes, EXPORTER, cache, 0, &limits),
        IPFIX => parse_ipfix(bytes, EXPORTER, cache, 0, &limits),
        _ => parse_netflow_v5(bytes, &limits),
    };
    Ok(batch.map_err(|reason| format!("dropped: {reason}"))?)
}


fn feed(map: &mut ServiceMap, files: &[&String]) -> Result<(), Box<dyn Error>> {
    let mut cache = TemplateCache::default();
    let now_ms = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    files.iter().try_for_each(|path| {
        let batch = parse(&read_capped(path, MAX_TEMPLATE_DATAGRAM_BYTES)?, &mut cache)?;
        batch.records.iter().for_each(|record| {
            observe(map, EXAMPLE_TENANT, record, now_ms);
        });
        Ok::<(), Box<dyn Error>>(())
    })
}


fn known_from(path: Option<&String>) -> Result<Vec<IpAddr>, Box<dyn Error>> {
    let text = path.map_or(Ok(String::new()), |name| {
        let mut text = String::new();
        std::fs::File::open(name)?.take(MAX_KNOWN_BYTES + 1).read_to_string(&mut text)?;
        if u64::try_from(text.len())? > MAX_KNOWN_BYTES {
            Err(format!(
                "the known-device file is longer than {MAX_KNOWN_BYTES} bytes, refused rather than cut"
            ))?;
        }
        Ok::<String, Box<dyn Error>>(text)
    })?;
    Ok(text.split_whitespace().map(str::parse).collect::<Result<Vec<IpAddr>, _>>()?)
}


fn flag_value<'a>(arguments: &'a [String], name: &str) -> Result<Option<&'a String>, Box<dyn Error>> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .map(|at| arguments.get(at + 1).ok_or(USAGE.into()))
        .transpose()
}


fn inventory_from(path: &str) -> Result<Vec<Asset>, Box<dyn Error>> {
    let text = String::from_utf8(read_capped(path, usize::try_from(MAX_KNOWN_BYTES)?)?)?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (id, mac) = line.split_once(' ').ok_or(USAGE)?;
            Ok(Asset {
                id: id.to_string(),
                kind: AssetKind::Workstation,
                lifecycle: Lifecycle::InService,
                keys: [(IdentityKey::Mac, mac.trim().to_string())].into_iter().collect(),
                attributes: Default::default(),
            })
        })
        .collect()
}


fn leases_from(path: &str) -> Result<Vec<core_export::ecs::EcsEvent>, Box<dyn Error>> {
    let text = String::from_utf8(read_capped(path, usize::try_from(MAX_LEASE_BYTES)?)?)?;
    let mut lines = text.lines();
    let columns = parse_header(lines.next().ok_or(USAGE)?)?;
    Ok(lines
        .map(|line| convert_row(&columns, line).map(|converted| converted.event))
        .collect::<Result<Vec<_>, _>>()?)
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let split = arguments
        .iter()
        .position(|argument| argument.starts_with("--"))
        .unwrap_or(arguments.len());
    let scope_path = arguments.first().filter(|_| split > 0).ok_or(USAGE)?;
    let files: Vec<&String> = arguments.iter().take(split).skip(1).collect();
    let known_path = flag_value(&arguments, "--known")?;
    let mut map = new_service_map(EXAMPLE_TENANT, load_scope(Path::new(scope_path))?)?;
    feed(&mut map, &files)?;
    let known = known_devices(known_from(known_path)?);
    let found = candidates(&map, &known);
    let mut out = std::io::stdout();
    edges(&map).try_for_each(|(key, stats)| writeln!(out, "{}", serde_json::json!({ "edge": key, "stats": stats })))?;
    found
        .iter()
        .try_for_each(|candidate| writeln!(out, "{}", serde_json::json!({ "candidate": candidate })))?;
    writeln!(out, "{}", serde_json::json!({ "counters": counters(&map) }))?;
    if let Some(leases_path) = flag_value(&arguments, "--leases")? {
        let inventory = inventory_from(flag_value(&arguments, "--inventory")?.ok_or(USAGE)?)?;
        let events = leases_from(leases_path)?;
        let hints = lease_hints(
            EXAMPLE_TENANT,
            events.iter().map(|event| TenantEvent {
                tenant: EXAMPLE_TENANT,
                event,
            }),
            &LeaseLimits::default(),
        );
        let (observed, observe_counters) = observations(EXAMPLE_TENANT, &found, &hints, &inventory, &ObserveLimits::default());
        observed.iter().try_for_each(|observation| {
            writeln!(
                out,
                "{}",
                serde_json::json!({ "observation": { "source": observation.source, "keys": observation.keys, "attributes": observation.attributes } })
            )
        })?;
        writeln!(
            out,
            "{}",
            serde_json::json!({ "hint_counters": hints.counters, "observe_counters": observe_counters })
        )?;
    }
    Ok(())
}
