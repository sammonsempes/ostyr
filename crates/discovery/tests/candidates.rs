#[path = "support/build.rs"]
mod build;
#[path = "support/types.rs"]
mod types;


use build::{flow, ip, map_with, CLIENT_PORT, HTTPS, ICMP, NOW_MS, TCP, TENANT, UDP};
use discovery::candidates::{candidates, known_devices};
use discovery::map::observe;
use discovery::model::{KnownDevices, ServiceRef, MAX_SERVICES_PER_CANDIDATE};
use std::error::Error;
use types::TestResult;


const SERVER: &str = "10.0.0.5";


const CLIENT: &str = "10.0.0.9";


const PRINTER: &str = "10.0.0.77";


const FOREIGN: &str = "203.0.113.7";


const DNS_PORT: u16 = 53;


const FIRST_SERVICE_PORT: u16 = 2000;


const EXTRA_SERVICES: usize = 8;


const BIG_CAP: usize = 100_000;


const EARLY: i64 = NOW_MS - 20_000;


const MIDDLE: i64 = NOW_MS - 10_000;


fn see(map: &mut discovery::model::ServiceMap, record: &site_collector::flow_model::FlowRecord) {
    observe(map, TENANT, record, NOW_MS);
}


#[test]
fn unknown_owned_addresses_are_listed_with_their_services() -> TestResult {
    let mut map = map_with(BIG_CAP, 1)?;
    see(&mut map, &flow(CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (EARLY, MIDDLE))?);
    see(&mut map, &flow(CLIENT, SERVER, (CLIENT_PORT, DNS_PORT), UDP, (MIDDLE, NOW_MS))?);
    see(&mut map, &flow(FOREIGN, SERVER, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?);
    see(&mut map, &flow(CLIENT, FOREIGN, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?);
    let found = candidates(&map, &KnownDevices::default());
    let addresses: Vec<_> = found.iter().map(|candidate| candidate.address).collect();
    assert_eq!(addresses, vec![ip(SERVER)?, ip(CLIENT)?]);
    let client = found.get(1).ok_or("client missing")?;
    assert!(client.services.is_empty());
    assert_eq!((client.first_seen_ms, client.last_seen_ms), (EARLY, NOW_MS));
    let server = found.first().ok_or("server missing")?;
    let expected = vec![
        ServiceRef {
            port: DNS_PORT,
            protocol: UDP,
        },
        ServiceRef { port: HTTPS, protocol: TCP },
    ];
    assert_eq!(server.services, expected);
    assert_eq!(server.services_omitted, 0);
    assert_eq!((server.first_seen_ms, server.last_seen_ms), (EARLY, NOW_MS));
    Ok(())
}


#[test]
fn known_devices_are_removed_in_any_notation() -> TestResult {
    let mut map = map_with(BIG_CAP, 1)?;
    see(&mut map, &flow(CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?);
    see(&mut map, &flow(PRINTER, SERVER, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?);
    let known = known_devices([ip("::ffff:10.0.0.5")?, ip(CLIENT)?]);
    let found = candidates(&map, &known);
    let addresses: Vec<_> = found.iter().map(|candidate| candidate.address).collect();
    assert_eq!(addresses, vec![ip(PRINTER)?]);
    let everything = known_devices([ip(SERVER)?, ip(CLIENT)?, ip(PRINTER)?]);
    assert!(candidates(&map, &everything).is_empty());
    Ok(())
}


#[test]
fn icmp_and_services_are_bounded_with_a_visible_count() -> TestResult {
    let mut map = map_with(BIG_CAP, 1)?;
    (0..MAX_SERVICES_PER_CANDIDATE + EXTRA_SERVICES).try_for_each(|offset| {
        let port = FIRST_SERVICE_PORT + u16::try_from(offset)?;
        see(&mut map, &flow(FOREIGN, SERVER, (CLIENT_PORT, port), TCP, (NOW_MS, NOW_MS))?);
        Ok::<(), Box<dyn Error>>(())
    })?;
    see(&mut map, &flow(FOREIGN, SERVER, (0, 0), ICMP, (NOW_MS, NOW_MS))?);
    let found = candidates(&map, &KnownDevices::default());
    let server = found.first().ok_or("server missing")?;
    assert_eq!(found.len(), 1);
    assert_eq!(server.services.len(), MAX_SERVICES_PER_CANDIDATE);
    assert_eq!(server.services_omitted, EXTRA_SERVICES + 1);
    assert_eq!(server.services.first(), Some(&ServiceRef { port: 0, protocol: ICMP }));
    Ok(())
}
