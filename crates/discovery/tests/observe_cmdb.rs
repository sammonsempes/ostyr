#[path = "support/assets.rs"]
mod assets;
#[path = "support/consts.rs"]
mod consts;
#[path = "support/types.rs"]
mod types;


use assets::asset_with_mac;
use cmdb::model::{IdentityKey, Observation};
use cmdb::reconcile::check_observation;
use consts::{CLTT, MAC_A};
use discovery::model::{Candidate, HintCounters, Lease, LeaseHints, ObserveLimits, ServiceRef};
use discovery::observe_cmdb::{asset_by_mac, observations, rfc3339_of, service_text};
use std::net::IpAddr;
use types::TestResult;


const TENANT: &str = "acme";


const KNOWN_ADDRESS: &str = "10.0.0.5";


const DNS: u16 = 53;


const HTTP: u16 = 80;


const DISCARD: u16 = 9;


const ECHO: u16 = 7;


const UDP: u8 = 17;


const TCP: u8 = 6;


const SCTP: u8 = 132;


const OTHER_PROTOCOL: u8 = 99;


const OMITTED: usize = 3;


const PAIR: u64 = 2;


const TWO_MACS: usize = 2;


const HUGE_HOSTNAME: usize = 5_000;


const BEFORE_YEAR_ZERO: i64 = 300_000_000_000_000;


const UNKNOWN_ADDRESS: &str = "10.0.0.6";


const MILLIS: i64 = 1000;


const SEEN_MS: i64 = 1_800_000_000_000;


fn candidate(address: &str, services: Vec<ServiceRef>, omitted: usize, last_seen_ms: i64) -> Result<Candidate, Box<dyn std::error::Error>> {
    Ok(Candidate {
        address: address.parse::<IpAddr>()?,
        first_seen_ms: SEEN_MS,
        last_seen_ms,
        services,
        services_omitted: omitted,
    })
}


fn hints(entries: &[(&str, &str, Option<&str>)]) -> Result<LeaseHints, Box<dyn std::error::Error>> {
    Ok(LeaseHints {
        tenant: "acme".to_string(),
        leases: entries
            .iter()
            .map(|(address, mac, hostname)| {
                Ok::<_, Box<dyn std::error::Error>>((
                    address.parse::<IpAddr>()?,
                    Lease {
                        mac: mac.to_string(),
                        hostname: hostname.map(str::to_string),
                        cltt: CLTT,
                        expires: i64::MAX,
                        released: false,
                    },
                ))
            })
            .collect::<Result<_, _>>()?,
        counters: HintCounters::default(),
    })
}


fn web() -> Vec<ServiceRef> {
    vec![
        ServiceRef { port: DNS, protocol: UDP },
        ServiceRef { port: HTTP, protocol: TCP },
        ServiceRef {
            port: DISCARD,
            protocol: SCTP,
        },
        ServiceRef { port: 0, protocol: 1 },
    ]
}


#[test]
fn a_known_mac_becomes_an_observation_and_an_unknown_one_is_counted() -> TestResult {
    let candidates = [
        candidate(KNOWN_ADDRESS, web(), OMITTED, SEEN_MS)?,
        candidate(UNKNOWN_ADDRESS, vec![], 0, SEEN_MS)?,
        candidate("10.0.0.7", vec![], 0, SEEN_MS)?,
    ];
    let lease_hints = hints(&[
        (KNOWN_ADDRESS, MAC_A, Some("printer-1")),
        (UNKNOWN_ADDRESS, "AA-BB-CC-DD-EE-99", Some("spoof")),
    ])?;
    let inventory = [asset_with_mac("mac:AA-BB-CC-DD-EE-01", MAC_A)];
    let (found, counters) = observations(TENANT, &candidates, &lease_hints, &inventory, &ObserveLimits::default());
    assert_eq!(found.len(), 1);
    assert_eq!(counters.observed, 1);
    assert_eq!(counters.unmatched, PAIR);
    let observation = found.first().ok_or("missing")?;
    assert_eq!(observation.source, "discovery");
    assert_eq!(observation.keys.len(), 1);
    assert_eq!(observation.keys.get(&IdentityKey::Mac).map(String::as_str), Some(MAC_A));
    assert_eq!(observation.attributes.get("discovery.ip").map(String::as_str), Some(KNOWN_ADDRESS));
    assert_eq!(observation.attributes.get("discovery.hostname").map(String::as_str), Some("printer-1"));
    assert_eq!(
        observation.attributes.get("discovery.services").map(String::as_str),
        Some("53/udp,80/tcp,9/sctp,0/1")
    );
    assert_eq!(observation.attributes.get("discovery.services_omitted").map(String::as_str), Some("3"));
    assert_eq!(
        observation.attributes.get("discovery.last_seen").map(String::as_str),
        Some("2027-01-15T08:00:00Z")
    );
    Ok(())
}


#[test]
fn the_hostname_is_an_attribute_never_a_key_even_when_reserved_looking() -> TestResult {
    let candidates = [candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?];
    let inventory = [asset_with_mac("a", MAC_A)];
    let (found, counters) = observations(
        TENANT,
        &candidates,
        &hints(&[(KNOWN_ADDRESS, MAC_A, Some("cmdb"))])?,
        &inventory,
        &ObserveLimits::default(),
    );
    let observation = found.first().ok_or("missing")?;
    assert_eq!(counters.rejected, 0);
    assert!(check_observation(observation).is_ok());
    assert_eq!(observation.keys.keys().collect::<Vec<_>>(), vec![&IdentityKey::Mac]);
    assert_eq!(observation.attributes.get("discovery.hostname").map(String::as_str), Some("cmdb"));
    assert!(observation.attributes.keys().all(|name| !name.starts_with("key:")));
    assert!(!observation.attributes.contains_key("discovery.services_omitted"));
    Ok(())
}


#[test]
fn an_observation_the_cmdb_checks_refuse_is_counted_never_returned() -> TestResult {
    let candidates = [candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?];
    let hostile = "a".repeat(HUGE_HOSTNAME);
    let inventory = [asset_with_mac("a", MAC_A)];
    let (found, counters) = observations(
        TENANT,
        &candidates,
        &hints(&[(KNOWN_ADDRESS, MAC_A, Some(&hostile))])?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert!(found.is_empty());
    assert_eq!(counters.rejected, 1);
    Ok(())
}


#[test]
fn times_out_of_range_are_refused() -> TestResult {
    let candidates = [
        candidate(KNOWN_ADDRESS, vec![], 0, i64::MAX)?,
        candidate("10.0.0.8", vec![], 0, -BEFORE_YEAR_ZERO)?,
    ];
    let inventory = [asset_with_mac("a", MAC_A)];
    let lease_hints = hints(&[(KNOWN_ADDRESS, MAC_A, None), ("10.0.0.8", MAC_A, None)])?;
    let (found, counters) = observations(TENANT, &candidates, &lease_hints, &inventory, &ObserveLimits::default());
    assert!(found.is_empty());
    assert_eq!(counters.rejected, PAIR);
    assert!(rfc3339_of(i64::MAX).is_err());
    assert!(rfc3339_of(-BEFORE_YEAR_ZERO).is_err());
    Ok(())
}


#[test]
fn observations_beyond_the_cap_are_counted() -> TestResult {
    let candidates = [candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?, candidate("10.0.0.8", vec![], 0, SEEN_MS)?];
    let inventory = [asset_with_mac("a", MAC_A)];
    let lease_hints = hints(&[(KNOWN_ADDRESS, MAC_A, None), ("10.0.0.8", MAC_A, None)])?;
    let (found, counters) = observations(TENANT, &candidates, &lease_hints, &inventory, &ObserveLimits { max_observations: 1 });
    assert_eq!(found.len(), 1);
    assert_eq!(counters.beyond_cap, 1);
    Ok(())
}


#[test]
fn the_first_asset_of_a_mac_wins_and_its_kind_is_used() -> TestResult {
    let mut second = asset_with_mac("second", MAC_A);
    second.kind = cmdb::model::AssetKind::Server;
    let inventory = [asset_with_mac("first", MAC_A), second];
    let (found, _) = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
        &hints(&[(KNOWN_ADDRESS, MAC_A, None)])?,
        &inventory,
        &ObserveLimits::default(),
    );
    let observation: &Observation = found.first().ok_or("missing")?;
    assert_eq!(observation.kind, cmdb::model::AssetKind::Printer);
    Ok(())
}


#[test]
fn an_asset_without_a_mac_key_matches_nothing() -> TestResult {
    let mut named = asset_with_mac("named", MAC_A);
    named.keys.clear();
    let (found, counters) = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
        &hints(&[(KNOWN_ADDRESS, MAC_A, None)])?,
        &[named],
        &ObserveLimits::default(),
    );
    assert!(found.is_empty());
    assert_eq!(counters.unmatched, 1);
    assert_eq!(
        service_text(&ServiceRef {
            port: ECHO,
            protocol: OTHER_PROTOCOL
        }),
        "7/99"
    );
    Ok(())
}


fn lease_hints_with(address: &str, expires: i64, released: bool, tenant: &str) -> Result<LeaseHints, Box<dyn std::error::Error>> {
    let mut found = hints(&[(address, MAC_A, None)])?;
    found.tenant = tenant.to_string();
    found.leases.values_mut().for_each(|lease| {
        lease.expires = expires;
        lease.released = released;
    });
    Ok(found)
}


#[test]
fn a_lease_hints_only_up_to_its_expiry() -> TestResult {
    let expiry_seconds = SEEN_MS / MILLIS;
    let inventory = [asset_with_mac("a", MAC_A)];
    let at_expiry = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
        &lease_hints_with(KNOWN_ADDRESS, expiry_seconds, false, TENANT)?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert_eq!(at_expiry.0.len(), 1);
    assert_eq!(at_expiry.1.expired, 0);
    let after_expiry = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS + 1)?],
        &lease_hints_with(KNOWN_ADDRESS, expiry_seconds, false, TENANT)?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert!(after_expiry.0.is_empty());
    assert_eq!(after_expiry.1.expired, 1);
    assert_eq!(after_expiry.1.unmatched, 0);
    Ok(())
}


#[test]
fn a_released_lease_never_hints() -> TestResult {
    let inventory = [asset_with_mac("a", MAC_A)];
    let (found, counters) = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
        &lease_hints_with(KNOWN_ADDRESS, i64::MAX, true, TENANT)?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert!(found.is_empty());
    assert_eq!(counters.released, 1);
    Ok(())
}


#[test]
fn hints_of_another_tenant_are_refused_and_counted() -> TestResult {
    let inventory = [asset_with_mac("a", MAC_A)];
    let (found, counters) = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
        &lease_hints_with(KNOWN_ADDRESS, i64::MAX, false, "globex")?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert!(found.is_empty());
    assert_eq!(counters.wrong_tenant, 1);
    assert_eq!(counters.unmatched, 0);
    Ok(())
}


#[test]
fn a_candidate_serving_nothing_has_no_services_attribute() -> TestResult {
    let inventory = [asset_with_mac("a", MAC_A)];
    let (found, _) = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
        &hints(&[(KNOWN_ADDRESS, MAC_A, None)])?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert!(!found.first().ok_or("missing")?.attributes.contains_key("discovery.services"));
    Ok(())
}


#[test]
fn the_mac_index_agrees_with_the_cmdb_first_asset_rule() -> TestResult {
    let inventory = [
        asset_with_mac("first", MAC_A),
        asset_with_mac("second", MAC_A),
        asset_with_mac("third", "AA-BB-CC-DD-EE-02"),
        asset_with_mac("fourth", "AA-BB-CC-DD-EE-02"),
    ];
    let index = asset_by_mac(&inventory);
    for mac in [MAC_A, "AA-BB-CC-DD-EE-02"] {
        let (found, _) = observations(
            TENANT,
            &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
            &hints(&[(KNOWN_ADDRESS, mac, None)])?,
            &inventory,
            &ObserveLimits::default(),
        );
        let observation = found.first().ok_or("missing")?;
        let expected = cmdb::reconcile::find_asset(&inventory, observation).ok_or("cmdb found none")?;
        assert_eq!(index.get(mac).ok_or("indexed none")?.id, expected.id);
    }
    assert_eq!(index.len(), TWO_MACS);
    Ok(())
}


fn candidate_between(first_seen_ms: i64, last_seen_ms: i64) -> Result<Candidate, Box<dyn std::error::Error>> {
    Ok(Candidate {
        first_seen_ms,
        ..candidate(KNOWN_ADDRESS, vec![], 0, last_seen_ms)?
    })
}


#[test]
fn a_flow_from_before_the_lease_is_not_attributed_to_it() -> TestResult {
    let inventory = [asset_with_mac("a", MAC_A)];
    let lease_start_ms = CLTT * MILLIS;
    let at_start = observations(
        TENANT,
        &[candidate_between(lease_start_ms, SEEN_MS)?],
        &hints(&[(KNOWN_ADDRESS, MAC_A, None)])?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert_eq!(at_start.0.len(), 1);
    assert_eq!(at_start.1.before_lease, 0);
    let before = observations(
        TENANT,
        &[candidate_between(lease_start_ms - 1, SEEN_MS)?],
        &hints(&[(KNOWN_ADDRESS, MAC_A, None)])?,
        &inventory,
        &ObserveLimits::default(),
    );
    assert!(before.0.is_empty());
    assert_eq!(before.1.before_lease, 1);
    assert_eq!(before.1.unmatched, 0);
    Ok(())
}


#[test]
fn a_released_lease_whose_mac_is_unknown_still_counts_released() -> TestResult {
    let mut found = lease_hints_with(KNOWN_ADDRESS, i64::MAX, true, TENANT)?;
    found.leases.values_mut().for_each(|lease| lease.mac.clear());
    let (observed, counters) = observations(
        TENANT,
        &[candidate(KNOWN_ADDRESS, vec![], 0, SEEN_MS)?],
        &found,
        &[asset_with_mac("a", MAC_A)],
        &ObserveLimits::default(),
    );
    assert!(observed.is_empty());
    assert_eq!(counters.released, 1);
    assert_eq!(counters.unmatched, 0);
    Ok(())
}
