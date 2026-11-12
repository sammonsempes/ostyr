#[path = "support/build.rs"]
mod build;
#[path = "support/types.rs"]
mod types;


use build::{flow, ip, map_with, CLIENT_PORT, DEFAULT_OCTETS, DEFAULT_PACKETS, HTTPS, ICMP, NOW_MS, TCP, TENANT, UDP};
use discovery::error::DiscoveryError;
use discovery::map::{counters, edge, edge_count, edge_key, edges, expire, new_service_map, observe, scope_of, seen_times, tenant_name};
use discovery::model::{EdgeKey, Observation, ScopeFile, ServiceMap, MILLIS_PER_DAY};
use discovery::scope::validate_scope;
use site_collector::flow_model::FlowRecord;
use std::error::Error;
use types::TestResult;


const SERVER: &str = "10.0.0.5";


const CLIENT: &str = "10.0.0.9";


const FOREIGN_A: &str = "203.0.113.7";


const FOREIGN_B: &str = "198.51.100.8";


const SSH_PORT: u16 = 22;


const DNS_PORT: u16 = 53;


const SCTP: u8 = 132;


const ICMP_ECHO_FIELD: u16 = 2048;


const HIGH_PORT: u16 = 50_001;


const PORT_A: u16 = 2000;


const PORT_B: u16 = 2001;


const PORT_C: u16 = 2002;


const PORT_D: u16 = 2003;


const PORT_E: u16 = 2004;


const BIG_CAP: usize = 100_000;


const SMALL_CAP: usize = 3;


const FLOOD_CAP: usize = 100;


const FLOOD_EDGES: u16 = 5000;


const RETENTION_DAYS: u32 = 1;


const YEAR_2100_MS: i64 = 4_102_444_800_000;


const MINUTE_MS: i64 = 60_000;


const TEN_SECONDS_MS: i64 = 10_000;


const TWENTY_SECONDS_MS: i64 = 20_000;


const STEP_1: i64 = NOW_MS - 6000;


const STEP_2: i64 = NOW_MS - 5000;


const STEP_3: i64 = NOW_MS - 4000;


const STEP_4: i64 = NOW_MS - 3000;


const STEP_5: i64 = NOW_MS - 2000;


const STEP_6: i64 = NOW_MS - 1000;


const TWO_DAYS_MS: i64 = 2 * MILLIS_PER_DAY;


const THREE_DAYS_MS: i64 = 3 * MILLIS_PER_DAY;


const TWICE: u64 = 2;


const THREE: usize = 3;


fn key(source: &str, destination: &str, port: u16, protocol: u8) -> Result<EdgeKey, Box<dyn Error>> {
    Ok(EdgeKey {
        source: ip(source)?,
        destination: ip(destination)?,
        port,
        protocol,
    })
}


fn port_flow(port: u16, at_ms: i64) -> Result<FlowRecord, Box<dyn Error>> {
    flow(CLIENT, SERVER, (CLIENT_PORT, port), TCP, (at_ms, at_ms))
}


fn see_port(map: &mut ServiceMap, port: u16, at_ms: i64) -> Result<Observation, Box<dyn Error>> {
    Ok(observe(map, TENANT, &port_flow(port, at_ms)?, NOW_MS))
}


fn has_port(map: &ServiceMap, port: u16) -> Result<bool, Box<dyn Error>> {
    Ok(edge(map, &key(CLIENT, SERVER, port, TCP)?).is_some())
}


#[test]
fn tenant_must_follow_the_core_pg_grammar() -> TestResult {
    let file = ScopeFile {
        owned_ranges: vec!["10.0.0.0/24".parse()?],
        retention_days: 1,
        max_edges: None,
    };
    let scope = validate_scope(&file)?;
    ["-x", "", "a b", "x/y"].iter().for_each(|bad| {
        assert!(matches!(new_service_map(bad, scope.clone()), Err(DiscoveryError::Tenant(_))), "{bad}");
    });
    let map = new_service_map(TENANT, scope.clone())?;
    assert_eq!(tenant_name(&map), TENANT);
    assert_eq!(scope_of(&map), &scope);
    assert_eq!(edge_count(&map), 0);
    Ok(())
}


#[test]
fn service_side_follows_the_port_rule() -> TestResult {
    let cases = [
        (CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (CLIENT, SERVER, HTTPS)),
        (SERVER, CLIENT, (HTTPS, CLIENT_PORT), TCP, (CLIENT, SERVER, HTTPS)),
        (CLIENT, SERVER, (CLIENT_PORT, HIGH_PORT), TCP, (CLIENT, SERVER, HIGH_PORT)),
        (CLIENT, SERVER, (SSH_PORT, DNS_PORT), TCP, (SERVER, CLIENT, SSH_PORT)),
        (CLIENT, SERVER, (DNS_PORT, SSH_PORT), TCP, (CLIENT, SERVER, SSH_PORT)),
        (CLIENT, SERVER, (DNS_PORT, DNS_PORT), UDP, (CLIENT, SERVER, DNS_PORT)),
        (SERVER, CLIENT, (DNS_PORT, CLIENT_PORT), UDP, (CLIENT, SERVER, DNS_PORT)),
        (CLIENT, SERVER, (0, ICMP_ECHO_FIELD), ICMP, (CLIENT, SERVER, 0)),
        (SERVER, CLIENT, (HTTPS, CLIENT_PORT), SCTP, (CLIENT, SERVER, HTTPS)),
        ("::ffff:10.0.0.9", "::ffff:10.0.0.5", (CLIENT_PORT, HTTPS), TCP, (CLIENT, SERVER, HTTPS)),
    ];
    cases.iter().try_for_each(|(source, destination, ports, protocol, expected)| {
        let record = flow(source, destination, *ports, *protocol, (NOW_MS, NOW_MS))?;
        assert_eq!(
            edge_key(&record),
            key(expected.0, expected.1, expected.2, *protocol)?,
            "{source} {destination} {ports:?}"
        );
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn both_directions_of_a_connection_share_one_edge() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let request = flow(CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (NOW_MS - TEN_SECONDS_MS, STEP_6))?;
    let reply = flow(SERVER, CLIENT, (HTTPS, CLIENT_PORT), TCP, (NOW_MS - TWENTY_SECONDS_MS, NOW_MS))?;
    assert_eq!(observe(&mut map, TENANT, &request, NOW_MS), Observation::Recorded);
    assert_eq!(observe(&mut map, TENANT, &reply, NOW_MS), Observation::Recorded);
    assert_eq!(edge_count(&map), 1);
    let stats = edge(&map, &key(CLIENT, SERVER, HTTPS, TCP)?).ok_or("edge missing")?;
    assert_eq!(stats.first_seen_ms, NOW_MS - TWENTY_SECONDS_MS);
    assert_eq!(stats.last_seen_ms, NOW_MS);
    assert_eq!(stats.flows, TWICE);
    assert_eq!(stats.packets, TWICE * DEFAULT_PACKETS);
    assert_eq!(stats.bytes, TWICE * DEFAULT_OCTETS);
    assert_eq!(counters(&map).recorded, TWICE);
    assert_eq!(edges(&map).count(), 1);
    Ok(())
}


#[test]
fn a_flow_needs_one_owned_end() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let inbound = flow(FOREIGN_A, SERVER, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?;
    let outbound = flow(SERVER, FOREIGN_A, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?;
    let foreign = flow(FOREIGN_A, FOREIGN_B, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?;
    assert_eq!(observe(&mut map, TENANT, &inbound, NOW_MS), Observation::Recorded);
    assert_eq!(observe(&mut map, TENANT, &outbound, NOW_MS), Observation::Recorded);
    assert_eq!(observe(&mut map, TENANT, &foreign, NOW_MS), Observation::OutOfScope);
    assert_eq!(observe(&mut map, TENANT, &foreign, NOW_MS), Observation::OutOfScope);
    assert_eq!(edge_count(&map), usize::try_from(TWICE)?);
    assert_eq!(counters(&map).out_of_scope, TWICE);
    assert!(edge(&map, &edge_key(&foreign)).is_none());
    Ok(())
}


#[test]
fn another_tenants_batch_changes_nothing_but_a_counter() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let record = flow(CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?;
    let tenants = ["other", "ACME", "acme ", ""];
    tenants.iter().for_each(|tenant| {
        assert_eq!(observe(&mut map, tenant, &record, NOW_MS), Observation::WrongTenant, "{tenant}");
    });
    assert_eq!(edge_count(&map), 0);
    assert_eq!(counters(&map).wrong_tenant, u64::try_from(tenants.len())?);
    assert_eq!(counters(&map).recorded, 0);
    Ok(())
}


#[test]
fn the_edge_with_the_oldest_last_seen_is_evicted_at_the_cap() -> TestResult {
    let mut map = map_with(SMALL_CAP, RETENTION_DAYS)?;
    see_port(&mut map, PORT_A, STEP_1)?;
    see_port(&mut map, PORT_B, STEP_2)?;
    see_port(&mut map, PORT_C, STEP_3)?;
    assert_eq!(edge_count(&map), SMALL_CAP);
    assert_eq!(counters(&map).evicted, 0);
    see_port(&mut map, PORT_D, STEP_4)?;
    assert_eq!(edge_count(&map), SMALL_CAP);
    assert_eq!(counters(&map).evicted, 1);
    assert!(!has_port(&map, PORT_A)?);
    assert!(has_port(&map, PORT_B)?);
    see_port(&mut map, PORT_B, STEP_5)?;
    assert_eq!(counters(&map).evicted, 1);
    see_port(&mut map, PORT_E, STEP_6)?;
    assert_eq!(counters(&map).evicted, TWICE);
    assert!(!has_port(&map, PORT_C)?);
    assert!(has_port(&map, PORT_B)?);
    assert_eq!(edge_count(&map), SMALL_CAP);
    Ok(())
}


#[test]
fn a_flood_of_distinct_edges_stays_at_the_cap() -> TestResult {
    let mut map = map_with(FLOOD_CAP, RETENTION_DAYS)?;
    (0..FLOOD_EDGES).try_for_each(|offset| {
        see_port(&mut map, PORT_A + offset, NOW_MS)?;
        assert!(edge_count(&map) <= FLOOD_CAP);
        Ok::<(), Box<dyn Error>>(())
    })?;
    assert_eq!(edge_count(&map), FLOOD_CAP);
    assert_eq!(counters(&map).evicted, u64::from(FLOOD_EDGES) - u64::try_from(FLOOD_CAP)?);
    assert_eq!(counters(&map).recorded, u64::from(FLOOD_EDGES));
    Ok(())
}


#[test]
fn expire_drops_edges_older_than_the_retention() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    see_port(&mut map, PORT_A, NOW_MS - TWO_DAYS_MS)?;
    see_port(&mut map, PORT_B, NOW_MS - MILLIS_PER_DAY)?;
    see_port(&mut map, PORT_C, NOW_MS)?;
    assert_eq!(edge_count(&map), THREE);
    assert_eq!(expire(&mut map, NOW_MS), 1);
    assert!(!has_port(&map, PORT_A)?);
    assert!(has_port(&map, PORT_B)?);
    assert_eq!(edge_count(&map), usize::try_from(TWICE)?);
    assert_eq!(counters(&map).expired, 1);
    assert_eq!(expire(&mut map, NOW_MS), 0);
    assert_eq!(expire(&mut map, NOW_MS + THREE_DAYS_MS), THREE - 1);
    assert_eq!(edge_count(&map), 0);
    assert_eq!(counters(&map).expired, u64::try_from(THREE)?);
    see_port(&mut map, PORT_A, NOW_MS)?;
    assert_eq!(edge_count(&map), 1);
    assert_eq!(expire(&mut map, NOW_MS + THREE_DAYS_MS), 1);
    Ok(())
}


#[test]
fn an_updated_edge_is_expired_by_its_new_last_seen() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    see_port(&mut map, PORT_A, NOW_MS - TWO_DAYS_MS)?;
    see_port(&mut map, PORT_A, NOW_MS)?;
    assert_eq!(expire(&mut map, NOW_MS), 0);
    assert_eq!(edge_count(&map), 1);
    Ok(())
}


fn seen_after(start_ms: i64, end_ms: i64) -> Result<(i64, i64, u64), Box<dyn Error>> {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let record = flow(CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (start_ms, end_ms))?;
    observe(&mut map, TENANT, &record, NOW_MS);
    let stats = edge(&map, &edge_key(&record)).ok_or("edge missing")?;
    Ok((stats.first_seen_ms, stats.last_seen_ms, counters(&map).clamped_times))
}


#[test]
fn hostile_times_never_date_an_edge_beyond_now() -> TestResult {
    assert_eq!(seen_after(0, 0)?, (NOW_MS, NOW_MS, 1));
    assert_eq!(seen_after(YEAR_2100_MS, YEAR_2100_MS)?, (NOW_MS, NOW_MS, 1));
    assert_eq!(seen_after(NOW_MS - TEN_SECONDS_MS, 0)?, (NOW_MS, NOW_MS, 1));
    assert_eq!(seen_after(0, NOW_MS - TEN_SECONDS_MS)?, (NOW_MS, NOW_MS, 1));
    assert_eq!(seen_after(i64::MIN, i64::MAX)?, (NOW_MS, NOW_MS, 1));
    assert_eq!(
        seen_after(NOW_MS - TWENTY_SECONDS_MS, NOW_MS + MINUTE_MS)?,
        (NOW_MS - TWENTY_SECONDS_MS, NOW_MS, 0)
    );
    assert_eq!(
        seen_after(NOW_MS - TEN_SECONDS_MS, NOW_MS - TWENTY_SECONDS_MS)?,
        (NOW_MS - TWENTY_SECONDS_MS, NOW_MS - TEN_SECONDS_MS, 0)
    );
    let record = flow(CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (0, 0))?;
    assert_eq!(seen_times(&record, NOW_MS), (NOW_MS, NOW_MS, true));
    Ok(())
}


#[test]
fn counters_saturate_instead_of_wrapping() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let mut record = flow(CLIENT, SERVER, (CLIENT_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?;
    record.octets = u64::MAX;
    record.packets = u64::MAX;
    observe(&mut map, TENANT, &record, NOW_MS);
    observe(&mut map, TENANT, &record, NOW_MS);
    let stats = edge(&map, &edge_key(&record)).ok_or("edge missing")?;
    assert_eq!((stats.bytes, stats.packets, stats.flows), (u64::MAX, u64::MAX, TWICE));
    Ok(())
}


const SERVICE_PORT: u16 = 8080;


const LOW_CLIENT_PORT: u16 = 900;


const SYN: u8 = 0x02;


const SYN_ACK: u8 = 0x12;


const ACK_ONLY: u8 = 0x10;


fn flagged(record: FlowRecord, flags: u8) -> FlowRecord {
    FlowRecord { tcp_flags: flags, ..record }
}


#[test]
fn a_service_above_1023_keeps_one_edge_with_its_replies() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let request = flagged(flow(CLIENT, SERVER, (CLIENT_PORT, SERVICE_PORT), TCP, (NOW_MS, NOW_MS))?, SYN_ACK);
    let reply = flagged(flow(SERVER, CLIENT, (SERVICE_PORT, CLIENT_PORT), TCP, (NOW_MS, NOW_MS))?, SYN_ACK);
    observe(&mut map, TENANT, &request, NOW_MS);
    observe(&mut map, TENANT, &reply, NOW_MS);
    assert_eq!(edge_count(&map), 1);
    let stats = edge(&map, &key(CLIENT, SERVER, SERVICE_PORT, TCP)?).ok_or("edge missing")?;
    assert_eq!(stats.flows, TWICE);
    Ok(())
}


#[test]
fn a_syn_from_a_higher_port_marks_the_destination_as_the_service() -> TestResult {
    let syn = flagged(flow(SERVER, CLIENT, (HIGH_PORT, SSH_PORT), TCP, (NOW_MS, NOW_MS))?, SYN);
    assert_eq!(edge_key(&syn), key(SERVER, CLIENT, SSH_PORT, TCP)?);
    let wins_over_low_source = flagged(flow(SERVER, CLIENT, (HIGH_PORT, HTTPS), TCP, (NOW_MS, NOW_MS))?, SYN);
    assert_eq!(edge_key(&wins_over_low_source), key(SERVER, CLIENT, HTTPS, TCP)?);
    let no_syn = flagged(flow(SERVER, CLIENT, (HIGH_PORT, SSH_PORT), TCP, (NOW_MS, NOW_MS))?, ACK_ONLY);
    assert_eq!(edge_key(&no_syn), key(SERVER, CLIENT, SSH_PORT, TCP)?);
    let udp = flagged(flow(CLIENT, SERVER, (SSH_PORT, DNS_PORT), UDP, (NOW_MS, NOW_MS))?, SYN);
    assert_eq!(edge_key(&udp), key(SERVER, CLIENT, SSH_PORT, UDP)?);
    let tcp_lower_source = flagged(flow(CLIENT, SERVER, (SSH_PORT, DNS_PORT), TCP, (NOW_MS, NOW_MS))?, SYN);
    assert_eq!(edge_key(&tcp_lower_source), key(SERVER, CLIENT, SSH_PORT, TCP)?);
    Ok(())
}


#[test]
fn a_client_syn_never_joins_the_reverse_edge_and_a_low_client_port_is_a_known_limit() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let request = flagged(flow(CLIENT, SERVER, (LOW_CLIENT_PORT, SERVICE_PORT), TCP, (NOW_MS, NOW_MS))?, SYN);
    let syn_ack = flagged(flow(SERVER, CLIENT, (SERVICE_PORT, LOW_CLIENT_PORT), TCP, (NOW_MS, NOW_MS))?, SYN_ACK);
    observe(&mut map, TENANT, &request, NOW_MS);
    observe(&mut map, TENANT, &syn_ack, NOW_MS);
    assert_eq!(
        edge(&map, &key(SERVER, CLIENT, LOW_CLIENT_PORT, TCP)?).ok_or("edge missing")?.flows,
        TWICE
    );
    let normal = flagged(flow(CLIENT, SERVER, (CLIENT_PORT, SERVICE_PORT), TCP, (NOW_MS, NOW_MS))?, SYN_ACK);
    observe(&mut map, TENANT, &normal, NOW_MS);
    let own = flagged(flow(SERVER, CLIENT, (HIGH_PORT, SERVICE_PORT), TCP, (NOW_MS, NOW_MS))?, SYN);
    observe(&mut map, TENANT, &own, NOW_MS);
    assert_eq!(edge(&map, &key(SERVER, CLIENT, SERVICE_PORT, TCP)?).ok_or("edge missing")?.flows, 1);
    assert_eq!(edge(&map, &key(CLIENT, SERVER, SERVICE_PORT, TCP)?).ok_or("edge missing")?.flows, 1);
    Ok(())
}


#[test]
fn a_reply_without_a_matching_edge_and_other_protocols_keep_their_own_edge() -> TestResult {
    let mut map = map_with(BIG_CAP, RETENTION_DAYS)?;
    let lonely_reply = flow(SERVER, CLIENT, (SERVICE_PORT, CLIENT_PORT), TCP, (NOW_MS, NOW_MS))?;
    observe(&mut map, TENANT, &lonely_reply, NOW_MS);
    assert_eq!(edge_count(&map), 1);
    assert!(edge(&map, &key(SERVER, CLIENT, CLIENT_PORT, TCP)?).is_some());
    let echo = flow(CLIENT, SERVER, (0, ICMP_ECHO_FIELD), ICMP, (NOW_MS, NOW_MS))?;
    let echo_reply = flow(SERVER, CLIENT, (0, 0), ICMP, (NOW_MS, NOW_MS))?;
    observe(&mut map, TENANT, &echo, NOW_MS);
    observe(&mut map, TENANT, &echo_reply, NOW_MS);
    assert_eq!(edge_count(&map), THREE);
    assert!(edge(&map, &key(SERVER, CLIENT, 0, ICMP)?).is_some());
    Ok(())
}
