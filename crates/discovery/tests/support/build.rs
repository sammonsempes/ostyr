use discovery::map::new_service_map;
use discovery::model::{ScopeFile, ServiceMap};
use discovery::scope::validate_scope;
use ipnet::IpNet;
use site_collector::flow_model::FlowRecord;
use std::error::Error;
use std::net::IpAddr;


pub const TENANT: &str = "acme";


pub const OWNED_RANGE: &str = "10.0.0.0/24";


pub const NOW_MS: i64 = 1_800_000_000_000;


pub const TCP: u8 = 6;


pub const UDP: u8 = 17;


pub const ICMP: u8 = 1;


pub const HTTPS: u16 = 443;


pub const CLIENT_PORT: u16 = 50_000;


pub const DEFAULT_PACKETS: u64 = 3;


pub const DEFAULT_OCTETS: u64 = 300;


pub fn ip(text: &str) -> Result<IpAddr, Box<dyn Error>> {
    Ok(text.parse()?)
}


pub fn flow(source: &str, destination: &str, ports: (u16, u16), protocol: u8, times: (i64, i64)) -> Result<FlowRecord, Box<dyn Error>> {
    Ok(FlowRecord {
        source: ip(source)?,
        destination: ip(destination)?,
        next_hop: ip(destination)?,
        input_interface: 0,
        output_interface: 0,
        packets: DEFAULT_PACKETS,
        octets: DEFAULT_OCTETS,
        start_unix_ms: times.0,
        end_unix_ms: times.1,
        source_port: ports.0,
        destination_port: ports.1,
        tcp_flags: 0,
        protocol,
        tos: 0,
        source_as: 0,
        destination_as: 0,
    })
}


pub fn map_with(max_edges: usize, retention_days: u32) -> Result<ServiceMap, Box<dyn Error>> {
    let file = ScopeFile {
        owned_ranges: vec![OWNED_RANGE.parse::<IpNet>()?],
        retention_days,
        max_edges: Some(max_edges),
    };
    Ok(new_service_map(TENANT, validate_scope(&file)?)?)
}
