use core_export::ecs::{to_json, EcsEvent};
use site_collector::event::{flow_events, trap_event};
use site_collector::flow::parse_netflow_v5;
use site_collector::flow_model::FlowLimits;
use site_collector::model::{TrapLimits, MAX_TRAP_BYTES};
use site_collector::snmp::parse_trap;
use std::error::Error;
use std::io::{stdout, Read, Write};
use std::net::IpAddr;
use time::OffsetDateTime;


const USAGE: &str = "usage: trap_flow_events <trap|flow> <datagram-file> <peer-ip>; prints one ECS JSON line per event";


const EXAMPLE_EPOCH: &str = "00000000000000000000000000000000";


fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let kind = arguments.next().ok_or(USAGE)?;
    let path = arguments.next().ok_or(USAGE)?;
    let peer: IpAddr = arguments.next().ok_or(USAGE)?.parse()?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(u64::try_from(MAX_TRAP_BYTES)? + 1)
        .read_to_end(&mut bytes)?;
    let now = OffsetDateTime::now_utc();
    let events: Vec<EcsEvent> = match kind.as_str() {
        "trap" => vec![trap_event(&parse_trap(&bytes, &TrapLimits::default())?, peer, EXAMPLE_EPOCH, 0, now)],
        "flow" => flow_events(&parse_netflow_v5(&bytes, &FlowLimits::default())?, peer, EXAMPLE_EPOCH, 0, now),
        _ => Err(USAGE)?,
    };
    events
        .iter()
        .try_for_each(|event| -> Result<(), Box<dyn Error>> { Ok(writeln!(stdout(), "{}", to_json(event)?)?) })
}
