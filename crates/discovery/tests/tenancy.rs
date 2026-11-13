#[path = "support/assets.rs"]
mod assets;
#[path = "support/types.rs"]
mod types;


use assets::asset_with_mac;
use dhcp_kea::header::parse_header;
use dhcp_kea::row::convert_row;
use discovery::leases::lease_hints;
use discovery::model::{Candidate, LeaseHints, LeaseLimits, ObserveLimits, TenantEvent};
use discovery::observe_cmdb::observations;
use std::net::IpAddr;
use types::TestResult;


const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context";


const TENANT: &str = "acme";


const ADDRESS: &str = "10.77.0.100";


const MAC_ONE: &str = "AA-BB-CC-DD-EE-01";


const MAC_TWO: &str = "AA-BB-CC-DD-EE-02";


const START: i64 = 1_800_000_000;


const LIFETIME: i64 = 3600;


const HALF: i64 = 1800;


const MILLIS: i64 = 1000;


const DECLINE_PROBATION: i64 = 86_400;


fn kea_mac(mac: &str) -> String {
    mac.replace('-', ":")
}


fn hints_of(rows: &[String]) -> Result<LeaseHints, Box<dyn std::error::Error>> {
    let columns = parse_header(HEADER)?;
    let events = rows
        .iter()
        .map(|row| convert_row(&columns, row).map(|converted| converted.event))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(lease_hints(
        TENANT,
        events.iter().map(|event| TenantEvent { tenant: TENANT, event }),
        &LeaseLimits::default(),
    ))
}


fn assignment(mac: &str, cltt: i64) -> String {
    format!("{ADDRESS},{},,{LIFETIME},{},1,0,0,,0,", kea_mac(mac), cltt + LIFETIME)
}


fn release(mac: &str, at: i64) -> String {
    format!("{ADDRESS},{},,0,{at},1,0,0,,0,", kea_mac(mac))
}


fn flow(first_seen_s: i64, last_seen_s: i64) -> Result<Candidate, Box<dyn std::error::Error>> {
    Ok(Candidate {
        address: ADDRESS.parse::<IpAddr>()?,
        first_seen_ms: first_seen_s * MILLIS,
        last_seen_ms: last_seen_s * MILLIS,
        services: vec![],
        services_omitted: 0,
    })
}


fn observed(hints: &LeaseHints, candidate: Candidate, mac: &str) -> (usize, u64) {
    let found = observations(TENANT, &[candidate], hints, &[asset_with_mac("a", mac)], &ObserveLimits::default());
    (found.0.len(), found.1.before_lease)
}


#[test]
fn a_renewal_by_the_same_mac_keeps_the_start_of_its_tenancy() -> TestResult {
    let hints = hints_of(&[assignment(MAC_ONE, START), assignment(MAC_ONE, START + HALF)])?;
    let lease = hints.leases.get(&ADDRESS.parse::<IpAddr>()?).ok_or("missing")?;
    assert_eq!(lease.cltt, START + HALF);
    assert_eq!(lease.tenancy_start, START);
    assert_eq!(observed(&hints, flow(START, START + HALF + 1)?, MAC_ONE), (1, 0));
    assert_eq!(observed(&hints, flow(START - 1, START + HALF + 1)?, MAC_ONE), (0, 1));
    Ok(())
}


#[test]
fn another_mac_after_a_release_starts_a_new_tenancy() -> TestResult {
    let hints = hints_of(&[
        assignment(MAC_ONE, START),
        release(MAC_ONE, START + HALF),
        assignment(MAC_TWO, START + LIFETIME),
    ])?;
    let lease = hints.leases.get(&ADDRESS.parse::<IpAddr>()?).ok_or("missing")?;
    assert_eq!(lease.tenancy_start, START + LIFETIME);
    assert_eq!(observed(&hints, flow(START + HALF + 1, START + LIFETIME + 1)?, MAC_TWO), (0, 1));
    assert_eq!(observed(&hints, flow(START + LIFETIME, START + LIFETIME + 1)?, MAC_TWO), (1, 0));
    Ok(())
}


#[test]
fn another_mac_without_a_release_starts_a_new_tenancy() -> TestResult {
    let hints = hints_of(&[assignment(MAC_ONE, START), assignment(MAC_TWO, START + HALF)])?;
    let lease = hints.leases.get(&ADDRESS.parse::<IpAddr>()?).ok_or("missing")?;
    assert_eq!(lease.tenancy_start, START + HALF);
    Ok(())
}


#[test]
fn the_same_mac_after_a_release_also_starts_a_new_tenancy() -> TestResult {
    let hints = hints_of(&[
        assignment(MAC_ONE, START),
        release(MAC_ONE, START + HALF),
        assignment(MAC_ONE, START + LIFETIME),
    ])?;
    let lease = hints.leases.get(&ADDRESS.parse::<IpAddr>()?).ok_or("missing")?;
    assert_eq!(lease.tenancy_start, START + LIFETIME);
    Ok(())
}


#[test]
fn a_real_kea_decline_row_releases_the_address() -> TestResult {
    let decline = format!("{ADDRESS},,,{DECLINE_PROBATION},{},1,0,0,,1,", START + HALF + DECLINE_PROBATION);
    let hints = hints_of(&[assignment(MAC_ONE, START), decline])?;
    let lease = hints.leases.get(&ADDRESS.parse::<IpAddr>()?).ok_or("missing")?;
    assert!(lease.released);
    assert!(lease.mac.is_empty());
    assert_eq!(hints.counters.released, 1);
    assert_eq!(observed(&hints, flow(START + HALF, START + HALF + 1)?, MAC_ONE), (0, 0));
    Ok(())
}
