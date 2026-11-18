use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use cmdb::model::{Asset, AssetKind, IdentityKey, Lifecycle};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use dhcp_kea::header::parse_header;
use dhcp_kea::row::convert_row;
use discovery::alerting::raise_unmanaged_alerts;
use discovery::candidates::{candidates, known_devices};
use discovery::cursor::{MIGRATIONS as CURSOR_MIGRATIONS, MIGRATION_NAMESPACE as CURSOR_NAMESPACE};
use discovery::leases::lease_hints;
use discovery::map::{counters, edges, new_service_map, observe};
use discovery::model::ServiceMap;
use discovery::model::{Candidate, KnownDevices, LeaseHints, LeaseLimits, ObserveLimits, Skipped, Stored, TenantEvent};
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};


const USAGE: &str =
    "usage: service_map <scope.yaml> <flow-datagram-file>... [--known <addresses-file>] [--leases <kea-leases4.csv> --inventory <id-mac-file>] [--alerts <pg.yaml> <tenant>]";


const EXAMPLE_TENANT: &str = "example";


const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);


const ALERT_DEADLINE: Duration = Duration::from_secs(30);


const TENANT_OFFSET: usize = 2;


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


fn feed(map: &mut ServiceMap, tenant: &str, files: &[&String]) -> Result<(), Box<dyn Error>> {
    let mut cache = TemplateCache::default();
    let now_ms = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    files.iter().try_for_each(|path| {
        let batch = parse(&read_capped(path, MAX_TEMPLATE_DATAGRAM_BYTES)?, &mut cache)?;
        batch.records.iter().for_each(|record| {
            observe(map, tenant, record, now_ms);
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


fn leases_from(path: &str) -> Result<(Vec<core_export::ecs::EcsEvent>, usize), Box<dyn Error>> {
    let text = String::from_utf8(read_capped(path, usize::try_from(MAX_LEASE_BYTES)?)?)?;
    let mut lines = text.lines();
    let columns = parse_header(lines.next().ok_or(USAGE)?)?;
    Ok(
        lines.fold((Vec::new(), 0), |(mut events, refused), line| match convert_row(&columns, line) {
            Ok(converted) => {
                events.push(converted.event);
                (events, refused)
            }
            Err(error) => {
                tracing::warn!("a lease row was refused: {error}");
                (events, refused + 1)
            }
        }),
    )
}


fn alerts_tenant(arguments: &[String]) -> Result<&str, Box<dyn Error>> {
    let at = arguments.iter().position(|argument| argument == "--alerts");
    at.map_or(Ok(EXAMPLE_TENANT), |found| {
        arguments.get(found + TENANT_OFFSET).map(String::as_str).ok_or(USAGE.into())
    })
}


async fn store_alerts(
    settings_file: &Path,
    scope: &TenantScope,
    found: &[Candidate],
    hints: &LeaseHints,
    inventory: &[Asset],
    known: &KnownDevices,
) -> Result<(Skipped, Stored), Box<dyn Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, ALERT_DEADLINE).await?;
    migrate(&client, CURSOR_NAMESPACE, &CURSOR_MIGRATIONS, ALERT_DEADLINE).await?;
    let exec = pg_executor(&client, ALERT_DEADLINE);
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    Ok(raise_unmanaged_alerts(&exec, scope, found, hints, inventory, known, now).await)
}


fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| error.to_string())?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let split = arguments
        .iter()
        .position(|argument| argument.starts_with("--"))
        .unwrap_or(arguments.len());
    let scope_path = arguments.first().filter(|_| split > 0).ok_or(USAGE)?;
    let files: Vec<&String> = arguments.iter().take(split).skip(1).collect();
    let known_path = flag_value(&arguments, "--known")?;
    let tenant = alerts_tenant(&arguments)?;
    let mut map = new_service_map(tenant, load_scope(Path::new(scope_path))?)?;
    feed(&mut map, tenant, &files)?;
    let known = known_devices(known_from(known_path)?);
    let found = candidates(&map, &known);
    let mut out = std::io::stdout();
    edges(&map).try_for_each(|(key, stats)| writeln!(out, "{}", serde_json::json!({ "edge": key, "stats": stats })))?;
    found
        .iter()
        .try_for_each(|candidate| writeln!(out, "{}", serde_json::json!({ "candidate": candidate })))?;
    writeln!(out, "{}", serde_json::json!({ "counters": counters(&map) }))?;
    let (events, refused_rows) = flag_value(&arguments, "--leases")?.map_or(Ok((Vec::new(), 0)), |path| leases_from(path))?;
    let inventory = flag_value(&arguments, "--inventory")?.map_or(Ok(Vec::new()), |path| inventory_from(path))?;
    let hints = lease_hints(tenant, events.iter().map(|event| TenantEvent { tenant, event }), &LeaseLimits::default());
    if flag_value(&arguments, "--leases")?.is_some() {
        let (observed, observe_counters) = observations(tenant, &found, &hints, &inventory, &ObserveLimits::default());
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
            serde_json::json!({ "hint_counters": hints.counters, "observe_counters": observe_counters, "refused_lease_rows": refused_rows })
        )?;
    }
    if let Some(settings_path) = flag_value(&arguments, "--alerts")? {
        let scope = tenant_scope(tenant)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (skipped, stored) = runtime.block_on(store_alerts(Path::new(settings_path), &scope, &found, &hints, &inventory, &known))?;
        writeln!(out, "{}", serde_json::json!({ "skipped": skipped, "stored": stored }))?;
    }
    Ok(())
}
