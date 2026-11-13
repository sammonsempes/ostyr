#[path = "support/consts.rs"]
mod consts;
#[path = "support/kea.rs"]
mod kea;
#[path = "support/types.rs"]
mod types;


use consts::{CLTT, MAC_A};
use core_export::ecs::EcsEvent;
use discovery::leases::{lease_hints, lease_of, Skip};
use discovery::model::{LeaseLimits, TenantEvent};
use kea::{lease_event, lease_event_at, LIFETIME};
use std::error::Error;
use std::net::IpAddr;
use types::TestResult;


const TENANT: &str = "acme";


const STEP: i64 = 10;


const LONG_HOSTNAME: usize = 300;


const HOSTILE_COUNT: u64 = 5;


const HOSTILE_LEN: usize = 5;


const PROBES: u32 = 4;


const SMALL_CAP: usize = 3;


const DEFAULT_CAP: u32 = 100_000;


const TEN_NET: u32 = 0x0a00_0000;


const PAIR: u64 = 2;


fn hints_of(events: &[EcsEvent], tenant: &str, limits: &LeaseLimits) -> discovery::model::LeaseHints {
    lease_hints(tenant, events.iter().map(|event| TenantEvent { tenant: TENANT, event }), limits)
}


#[test]
fn the_latest_lease_of_an_address_wins() -> TestResult {
    let events = [
        lease_event("10.0.0.5", Some(MAC_A), Some("old"), CLTT)?,
        lease_event("10.0.0.5", Some("AA-BB-CC-DD-EE-02"), Some("new"), CLTT + STEP)?,
        lease_event("10.0.0.5", Some(MAC_A), Some("stale"), CLTT - STEP)?,
    ];
    let hints = hints_of(&events, TENANT, &LeaseLimits::default());
    let lease = hints.leases.get(&"10.0.0.5".parse::<IpAddr>()?).ok_or("missing")?;
    assert_eq!(lease.hostname.as_deref(), Some("new"));
    assert_eq!(lease.mac, "AA-BB-CC-DD-EE-02");
    assert_eq!(hints.leases.len(), 1);
    Ok(())
}


#[test]
fn an_event_of_another_tenant_is_counted_and_ignored() -> TestResult {
    let event = lease_event("10.0.0.5", Some(MAC_A), None, CLTT)?;
    let hints = lease_hints(
        "acme",
        [TenantEvent {
            tenant: "other",
            event: &event,
        }],
        &LeaseLimits::default(),
    );
    assert!(hints.leases.is_empty());
    assert_eq!(hints.counters.wrong_tenant, 1);
    Ok(())
}


#[test]
fn hostile_hostnames_are_dropped_and_counted() -> TestResult {
    let long = "a".repeat(LONG_HOSTNAME);
    let names = ["bad\u{202e}name", "-leading", "tab\tname", long.as_str(), "key:owner"];
    let events = names
        .iter()
        .enumerate()
        .map(|(index, name)| lease_event(&format!("10.0.0.{}", index + 1), Some(MAC_A), Some(name), CLTT))
        .collect::<Result<Vec<_>, _>>()?;
    let hints = hints_of(&events, TENANT, &LeaseLimits::default());
    assert_eq!(hints.counters.bad_hostname, HOSTILE_COUNT);
    assert!(hints.leases.values().all(|lease| lease.hostname.is_none()));
    assert_eq!(hints.leases.len(), HOSTILE_LEN);
    Ok(())
}


#[test]
fn a_valid_hostname_is_kept_and_a_missing_one_is_not_counted() -> TestResult {
    let events = [
        lease_event("10.0.0.1", Some(MAC_A), Some("printer-1.lan."), CLTT)?,
        lease_event("10.0.0.2", Some(MAC_A), None, CLTT)?,
    ];
    let hints = hints_of(&events, TENANT, &LeaseLimits::default());
    assert_eq!(hints.counters.bad_hostname, 0);
    assert_eq!(
        hints.leases.get(&"10.0.0.1".parse::<IpAddr>()?).ok_or("missing")?.hostname.as_deref(),
        Some("printer-1.lan")
    );
    Ok(())
}


#[test]
fn addresses_beyond_the_cap_are_counted_not_buffered() -> TestResult {
    let events = (1..=PROBES)
        .map(|index| lease_event(&format!("10.0.0.{index}"), Some(MAC_A), None, CLTT))
        .collect::<Result<Vec<_>, _>>()?;
    let mut again = lease_event("10.0.0.1", Some(MAC_A), None, CLTT + 1)?;
    again.event.action = Some("lease-assigned".to_string());
    let all: Vec<EcsEvent> = events.into_iter().chain([again]).collect();
    let hints = hints_of(&all, TENANT, &LeaseLimits { max_leases: SMALL_CAP });
    assert_eq!(hints.leases.len(), SMALL_CAP);
    assert_eq!(hints.counters.beyond_cap, 1);
    assert_eq!(hints.leases.get(&"10.0.0.1".parse::<IpAddr>()?).ok_or("missing")?.cltt, CLTT + 1);
    Ok(())
}


#[test]
fn a_hundred_thousand_and_one_addresses_are_capped_by_default() -> TestResult {
    let total: u32 = DEFAULT_CAP + 1;
    let limits = LeaseLimits::default();
    let events = (0..total)
        .map(|index| lease_event(&std::net::Ipv4Addr::from(TEN_NET + index).to_string(), Some(MAC_A), None, CLTT))
        .collect::<Result<Vec<_>, _>>()?;
    let hints = hints_of(&events, TENANT, &limits);
    assert_eq!(hints.leases.len(), usize::try_from(DEFAULT_CAP)?);
    assert_eq!(hints.counters.beyond_cap, 1);
    Ok(())
}


#[test]
fn events_that_are_not_assigned_leases_are_counted_by_reason() -> TestResult {
    let mut other_dataset = lease_event("10.0.0.1", Some(MAC_A), None, CLTT)?;
    other_dataset.event.dataset = Some("other".to_string());
    let mut no_start = lease_event("10.0.0.1", Some(MAC_A), None, CLTT)?;
    no_start.event.start = None;
    let mut declined = lease_event("10.0.0.1", Some(MAC_A), None, CLTT)?;
    declined.event.action = Some("lease-state-3".to_string());
    let no_end = lease_event_at("10.0.0.1", Some(MAC_A), None, CLTT)?;
    let bad_address = lease_event("not-an-ip", Some(MAC_A), None, CLTT)?;
    let mut no_source = lease_event("10.0.0.1", Some(MAC_A), None, CLTT)?;
    no_source.source = None;
    let no_mac = lease_event("10.0.0.1", None, None, CLTT)?;
    let bad_mac = lease_event("10.0.0.1", Some("zz"), None, CLTT)?;
    let events = [other_dataset, no_start, declined, no_end, bad_address, no_source, no_mac, bad_mac];
    let hints = hints_of(&events, TENANT, &LeaseLimits::default());
    assert!(hints.leases.is_empty());
    assert_eq!(hints.counters.not_lease, PAIR);
    assert_eq!(hints.counters.not_assigned, 1);
    assert_eq!(hints.counters.bad_address, PAIR);
    assert_eq!(hints.counters.no_mac, PAIR);
    assert_eq!(hints.counters.no_expiry, 1);
    Ok(())
}


#[test]
fn a_mapped_address_is_canonical_and_lease_of_reports_skips() -> Result<(), Box<dyn Error>> {
    let mapped = lease_event("::ffff:10.0.0.9", Some("aa:bb:cc:dd:ee:01"), None, CLTT)?;
    let (address, lease) = lease_of(&mapped).map_err(|skip| format!("{skip:?}"))?;
    assert_eq!(address, "10.0.0.9".parse::<IpAddr>()?);
    assert_eq!(lease.mac, MAC_A);
    let mut declined = mapped;
    declined.event.action = None;
    assert_eq!(lease_of(&declined), Err(Skip::NotAssigned));
    Ok(())
}


fn with_action(event: EcsEvent, action: &str) -> EcsEvent {
    EcsEvent {
        event: core_export::ecs::EventFields {
            action: Some(action.to_string()),
            ..event.event
        },
        ..event
    }
}


#[test]
fn a_lease_keeps_its_expiry() -> TestResult {
    let events = [lease_event("10.0.0.5", Some(MAC_A), None, CLTT)?];
    let hints = hints_of(&events, TENANT, &LeaseLimits::default());
    let lease = hints.leases.get(&"10.0.0.5".parse::<IpAddr>()?).ok_or("missing")?;
    assert_eq!(lease.expires, CLTT + LIFETIME);
    assert!(!lease.released);
    Ok(())
}


#[test]
fn a_later_reclaim_or_decline_releases_the_address_and_is_counted() -> TestResult {
    for action in ["lease-expired-reclaimed", "lease-declined"] {
        let events = [
            lease_event("10.0.0.5", Some(MAC_A), None, CLTT)?,
            with_action(lease_event("10.0.0.5", Some(MAC_A), None, CLTT + STEP)?, action),
        ];
        let hints = hints_of(&events, TENANT, &LeaseLimits::default());
        assert!(hints.leases.get(&"10.0.0.5".parse::<IpAddr>()?).ok_or("missing")?.released);
        assert_eq!(hints.counters.released, 1);
        assert_eq!(hints.counters.not_assigned, 0);
    }
    Ok(())
}


#[test]
fn a_reclaim_older_than_the_assignment_changes_nothing() -> TestResult {
    let events = [
        lease_event("10.0.0.5", Some(MAC_A), None, CLTT)?,
        with_action(lease_event("10.0.0.5", Some(MAC_A), None, CLTT - STEP)?, "lease-expired-reclaimed"),
    ];
    let hints = hints_of(&events, TENANT, &LeaseLimits::default());
    assert!(!hints.leases.get(&"10.0.0.5".parse::<IpAddr>()?).ok_or("missing")?.released);
    Ok(())
}


#[test]
fn an_assignment_older_than_a_reclaim_does_not_revive_the_address() -> TestResult {
    let events = [
        with_action(lease_event("10.0.0.5", Some(MAC_A), None, CLTT)?, "lease-declined"),
        lease_event("10.0.0.5", Some(MAC_A), None, CLTT - STEP)?,
    ];
    let hints = hints_of(&events, TENANT, &LeaseLimits::default());
    assert!(hints.leases.get(&"10.0.0.5".parse::<IpAddr>()?).ok_or("missing")?.released);
    Ok(())
}
