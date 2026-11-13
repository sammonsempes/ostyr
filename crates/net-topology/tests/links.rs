#[path = "common/types.rs"]
mod types;


use net_topology::error::LinkError;
use net_topology::limits::DEFAULT_MAX_LINKS_PER_HOST;
use net_topology::links::{build_links, is_stale, link_key, merge_observations, MAX_STALE_AFTER_SECONDS};
use net_topology::model::{IdSubtype, Link, NeighbourId, Observation};
use types::TestResult;


const T0: i64 = 1_700_000_000;


const LATER: i64 = 1_700_000_100;


const CAP: usize = 3;


const FAKE_BATCHES: usize = 50;


const FAKES_PER_BATCH: usize = 100;


const THRESHOLD: i64 = 600;


const PORT_CAP: usize = 16;


const FAKE_PORT_FLOOD: usize = 2_000;


fn id(value: &str) -> NeighbourId {
    NeighbourId {
        subtype: IdSubtype::IfName,
        value: value.to_owned(),
    }
}


fn observation(host: &str, chassis: &str, seen: i64) -> Observation {
    Observation {
        local_host: host.to_owned(),
        local_port: "eth0".to_owned(),
        remote_chassis: id(chassis),
        remote_port: id("p1"),
        remote_name: Some(format!("name-{chassis}")),
        seen,
    }
}


fn links_of(tenant: &str, observations: Vec<Observation>) -> Result<Vec<Link>, LinkError> {
    build_links(tenant, observations)
}


fn one_link(chassis: &str, seen: i64) -> Result<Link, Box<dyn std::error::Error>> {
    links_of("lab", vec![observation("server", chassis, seen)])?
        .into_iter()
        .next()
        .ok_or("no link".into())
}


#[test]
fn links_carry_the_tenant_and_the_observation_time() -> TestResult {
    let link = one_link("a", T0)?;
    assert_eq!(link.first_seen, T0);
    assert_eq!(link.last_seen, T0);
    assert_eq!(link.remote_name.as_deref(), Some("name-a"));
    assert_eq!(link_key(&link), ("server".to_owned(), "eth0".to_owned(), id("a"), id("p1")));
    Ok(())
}


#[test]
fn an_invalid_tenant_is_refused() -> TestResult {
    ["", "-x", "a b", "x/y"].iter().for_each(|tenant| {
        assert!(matches!(
            links_of(tenant, vec![observation("server", "a", T0)]),
            Err(LinkError::Tenant(_))
        ))
    });
    Ok(())
}


#[test]
fn inputs_of_two_tenants_are_refused() -> TestResult {
    let previous = links_of("lab", vec![observation("server", "a", T0)])?;
    let observed = links_of("other", vec![observation("server", "a", LATER)])?;
    assert!(matches!(
        merge_observations(previous.clone(), observed.clone(), LATER, CAP, CAP),
        Err(LinkError::TenantMismatch)
    ));
    assert!(matches!(
        merge_observations(observed, previous, LATER, CAP, CAP),
        Err(LinkError::TenantMismatch)
    ));
    Ok(())
}


#[test]
fn a_known_link_updates_its_last_seen_and_keeps_its_first_seen() -> TestResult {
    let previous = vec![one_link("a", T0)?];
    let observed = vec![one_link("a", LATER)?];
    let merged = merge_observations(previous, observed, LATER, CAP, CAP)?;
    let link = merged.links.first().ok_or("no link")?;
    assert_eq!(merged.links.len(), 1);
    assert_eq!((link.first_seen, link.last_seen), (T0, LATER));
    assert_eq!(merged.refused_new, 0);
    Ok(())
}


#[test]
fn last_seen_never_goes_backwards() -> TestResult {
    let merged = merge_observations(vec![one_link("a", LATER)?], vec![one_link("a", T0)?], T0, CAP, CAP)?;
    assert_eq!(merged.links.first().ok_or("no link")?.last_seen, LATER);
    Ok(())
}


#[test]
fn a_new_link_is_added_and_an_absent_link_is_never_removed() -> TestResult {
    let merged = merge_observations(vec![one_link("a", T0)?], vec![one_link("b", LATER)?], LATER, CAP, CAP)?;
    let names = merged.links.iter().map(|link| link.remote_chassis.value.as_str()).collect::<Vec<_>>();
    assert_eq!(names, ["a", "b"]);
    let added = merged.links.get(1).ok_or("no second link")?;
    assert_eq!((added.first_seen, added.last_seen), (LATER, LATER));
    let kept = merged.links.first().ok_or("no first link")?;
    assert_eq!((kept.first_seen, kept.last_seen), (T0, T0));
    Ok(())
}


#[test]
fn a_repeated_observation_counts_once_and_the_display_name_follows() -> TestResult {
    let mut renamed = one_link("a", LATER)?;
    renamed.remote_name = Some("renamed".to_owned());
    let merged = merge_observations(Vec::new(), vec![one_link("a", LATER)?, renamed], LATER, CAP, CAP)?;
    assert_eq!(merged.links.len(), 1);
    assert_eq!(merged.links.first().ok_or("no link")?.remote_name.as_deref(), Some("renamed"));
    Ok(())
}


#[test]
fn the_per_host_cap_refuses_new_links_and_keeps_known_ones_current() -> TestResult {
    let previous = links_of(
        "lab",
        vec![
            observation("server", "a", T0),
            observation("server", "b", T0),
            observation("server", "c", T0),
        ],
    )?;
    let observed = links_of(
        "lab",
        vec![
            observation("server", "x", LATER),
            observation("server", "a", LATER),
            observation("other", "x", LATER),
        ],
    )?;
    let merged = merge_observations(previous, observed, LATER, CAP, CAP)?;
    assert_eq!(merged.refused_new, 1);
    assert_eq!(merged.links.len(), CAP + 1);
    let known = merged
        .links
        .iter()
        .find(|link| link.remote_chassis.value == "a" && link.local_host == "server");
    assert_eq!(known.ok_or("known link lost")?.last_seen, LATER);
    assert!(merged
        .links
        .iter()
        .all(|link| link.remote_chassis.value != "x" || link.local_host == "other"));
    Ok(())
}


#[test]
fn a_flood_of_fake_chassis_cannot_evict_known_links() -> TestResult {
    let real = one_link("0real", T0)?;
    let first_batch = merge_observations(vec![real], Vec::new(), T0, DEFAULT_MAX_LINKS_PER_HOST, DEFAULT_MAX_LINKS_PER_HOST)?;
    let outcome = (0..FAKE_BATCHES).try_fold((first_batch.links, 0), |(links, refused), batch| -> Result<_, LinkError> {
        let fakes = (0..FAKES_PER_BATCH)
            .map(|index| observation("server", &format!("fake-{batch}-{index}"), LATER))
            .collect();
        let merged = merge_observations(
            links,
            links_of("lab", fakes)?,
            LATER,
            DEFAULT_MAX_LINKS_PER_HOST,
            DEFAULT_MAX_LINKS_PER_HOST,
        )?;
        Ok((merged.links, refused + merged.refused_new))
    })?;
    let (links, refused) = outcome;
    assert_eq!(links.len(), DEFAULT_MAX_LINKS_PER_HOST);
    assert_eq!(refused, FAKE_BATCHES * FAKES_PER_BATCH - (DEFAULT_MAX_LINKS_PER_HOST - 1));
    assert!(links.iter().any(|link| link.remote_chassis.value == "0real" && link.first_seen == T0));
    Ok(())
}


#[test]
fn staleness_is_decided_at_exactly_the_threshold() -> TestResult {
    let link = one_link("a", T0)?;
    assert!(!is_stale(&link, T0 + THRESHOLD - 1, THRESHOLD)?);
    assert!(is_stale(&link, T0 + THRESHOLD, THRESHOLD)?);
    assert!(is_stale(&link, T0 + THRESHOLD + 1, THRESHOLD)?);
    assert!(!is_stale(&link, T0 - THRESHOLD, THRESHOLD)?);
    Ok(())
}


#[test]
fn the_staleness_window_is_one_second_to_thirty_days() -> TestResult {
    let link = one_link("a", T0)?;
    [0, -1, MAX_STALE_AFTER_SECONDS + 1, i64::MAX]
        .iter()
        .for_each(|bad| assert!(matches!(is_stale(&link, T0, *bad), Err(LinkError::InvalidStaleAfter { .. }))));
    assert!(is_stale(&link, T0 + MAX_STALE_AFTER_SECONDS, MAX_STALE_AFTER_SECONDS)?);
    assert!(is_stale(&link, T0 + 1, 1)?);
    Ok(())
}


fn observation_on(port: &str, chassis: &str, seen: i64) -> Observation {
    Observation {
        local_port: port.to_owned(),
        ..observation("server", chassis, seen)
    }
}


#[test]
fn one_hostile_port_stops_at_its_cap_and_leaves_room_on_other_ports() -> TestResult {
    let fakes = (0..FAKE_PORT_FLOOD)
        .map(|index| observation_on("eth0", &format!("fake-{index}"), LATER))
        .collect();
    let first = merge_observations(Vec::new(), links_of("lab", fakes)?, LATER, DEFAULT_MAX_LINKS_PER_HOST, PORT_CAP)?;
    assert_eq!(first.links.len(), PORT_CAP);
    assert_eq!(first.refused_new, FAKE_PORT_FLOOD - PORT_CAP);
    let real = links_of("lab", vec![observation_on("eth1", "real", LATER)])?;
    let second = merge_observations(first.links, real, LATER, DEFAULT_MAX_LINKS_PER_HOST, PORT_CAP)?;
    assert_eq!(second.links.len(), PORT_CAP + 1);
    assert_eq!(second.refused_new, 0);
    assert!(second.links.iter().any(|link| link.local_port == "eth1"));
    Ok(())
}


#[test]
fn the_host_cap_still_applies_across_ports() -> TestResult {
    let observed = ["eth0", "eth1", "eth2", "eth3"]
        .iter()
        .map(|port| observation_on(port, "a", LATER))
        .collect();
    let merged = merge_observations(Vec::new(), links_of("lab", observed)?, LATER, CAP, PORT_CAP)?;
    assert_eq!((merged.links.len(), merged.refused_new), (CAP, 1));
    Ok(())
}
