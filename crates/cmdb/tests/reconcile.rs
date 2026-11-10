#[path = "common/types.rs"]
mod types;


use cmdb::error::CmdbError;
use cmdb::model::{Asset, AssetKind, Attribute, Event, IdentityKey, Lifecycle, Observation, Resolution};
use cmdb::reconcile::{find_asset, new_asset, reconcile};
use cmdb::types::TruthMap;
use std::collections::BTreeMap;
use types::TestResult;


const AFTER_CREATION: usize = 2;


fn observation(source: &str, keys: &[(IdentityKey, &str)], attributes: &[(&str, &str)]) -> Observation {
    Observation {
        source: source.to_string(),
        kind: AssetKind::Server,
        keys: keys.iter().map(|(key, value)| (*key, value.to_string())).collect(),
        attributes: attributes.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect(),
    }
}


fn asset(id: &str, keys: &[(IdentityKey, &str)], lifecycle: Lifecycle) -> Asset {
    Asset {
        id: id.to_string(),
        kind: AssetKind::Server,
        lifecycle,
        keys: keys.iter().map(|(key, value)| (*key, value.to_string())).collect(),
        attributes: BTreeMap::new(),
    }
}


fn truth(pairs: &[(&str, &str)]) -> TruthMap {
    pairs.iter().map(|(name, source)| (name.to_string(), source.to_string())).collect()
}


fn attribute(value: &str, source: &str) -> Attribute {
    Attribute {
        value: value.to_string(),
        source: source.to_string(),
    }
}


fn with_owner(owner: &str, source: &str) -> Asset {
    let mut existing = asset("a", &[(IdentityKey::Name, "web1")], Lifecycle::InService);
    existing.attributes.insert("owner".to_string(), attribute(owner, source));
    existing
}


#[test]
fn strongest_key_wins_over_weaker_match() -> TestResult {
    let inventory = vec![
        asset("by-name", &[(IdentityKey::Name, "web1")], Lifecycle::InService),
        asset("by-serial", &[(IdentityKey::SerialNumber, "SN1")], Lifecycle::InService),
    ];
    let seen = observation("osquery", &[(IdentityKey::Name, "web1"), (IdentityKey::SerialNumber, "SN1")], &[]);
    let found = find_asset(&inventory, &seen).map(|found| found.id.clone());
    assert_eq!(found, Some("by-serial".to_string()));
    Ok(())
}


#[test]
fn weaker_key_matches_when_stronger_is_unknown() -> TestResult {
    let inventory = vec![asset("a", &[(IdentityKey::Name, "web1")], Lifecycle::InService)];
    let seen = observation("dhcp", &[(IdentityKey::Mac, "aa"), (IdentityKey::Name, "web1")], &[]);
    let outcome = reconcile(&inventory, &seen, &TruthMap::new())?;
    assert_eq!(outcome.inventory.len(), 1);
    let merged = outcome.inventory.first().ok_or("empty")?;
    assert_eq!(merged.keys.get(&IdentityKey::Mac), Some(&"aa".to_string()));
    assert_eq!(merged.keys.get(&IdentityKey::Name), Some(&"web1".to_string()));
    assert!(outcome.events.is_empty());
    Ok(())
}


#[test]
fn unknown_observation_creates_asset_without_touching_input() -> TestResult {
    let inventory = vec![asset("a", &[(IdentityKey::Name, "web1")], Lifecycle::InService)];
    let before = inventory.clone();
    let seen = observation("osquery", &[(IdentityKey::Mac, "bb"), (IdentityKey::Name, "db1")], &[("os", "linux")]);
    let outcome = reconcile(&inventory, &seen, &TruthMap::new())?;
    assert_eq!(inventory, before);
    assert_eq!(outcome.inventory.len(), AFTER_CREATION);
    let created = outcome.inventory.get(1).ok_or("missing")?;
    assert_eq!(created.id, "mac:bb");
    assert_eq!(created.lifecycle, Lifecycle::InService);
    assert_eq!(created.attributes.get("os"), Some(&attribute("linux", "osquery")));
    assert_eq!(outcome.events, vec![Event::Created { asset: "mac:bb".to_string() }]);
    Ok(())
}


#[test]
fn a_derived_id_owned_by_another_asset_is_refused_and_never_overwrites_it() -> TestResult {
    let inventory = vec![asset("serial_number:SN9", &[(IdentityKey::Name, "other")], Lifecycle::InService)];
    let seen = observation("osquery", &[(IdentityKey::SerialNumber, "SN9")], &[("os", "linux")]);
    let refused = reconcile(&inventory, &seen, &TruthMap::new()).err().ok_or("accepted")?;
    assert_eq!(
        refused,
        CmdbError::IdCollision {
            id: "serial_number:SN9".to_string()
        }
    );
    assert!(refused.to_string().contains("serial_number:SN9"));
    Ok(())
}


#[test]
fn observation_without_key_is_refused() -> TestResult {
    let seen = observation("dhcp", &[], &[]);
    assert_eq!(
        new_asset(&seen).err(),
        Some(CmdbError::NoIdentity {
            source_name: "dhcp".to_string()
        })
    );
    let refused = reconcile(&[], &seen, &TruthMap::new()).err().ok_or("accepted")?;
    assert!(refused.to_string().contains("dhcp"));
    Ok(())
}


#[test]
fn source_of_truth_overrides_and_conflict_is_logged() -> TestResult {
    let seen = observation("git", &[(IdentityKey::Name, "web1")], &[("owner", "bob")]);
    let outcome = reconcile(&[with_owner("alice", "rmm")], &seen, &truth(&[("owner", "git")]))?;
    let merged = outcome.inventory.first().ok_or("empty")?;
    assert_eq!(merged.attributes.get("owner"), Some(&attribute("bob", "git")));
    assert_eq!(outcome.conflicts.len(), 1);
    let conflict = outcome.conflicts.first().ok_or("none")?;
    assert_eq!(conflict.asset, "a");
    assert_eq!(conflict.attribute, "owner");
    assert_eq!(conflict.current, attribute("alice", "rmm"));
    assert_eq!(conflict.observed, attribute("bob", "git"));
    assert_eq!(conflict.resolution, Resolution::TookObserved);
    Ok(())
}


#[test]
fn non_authoritative_source_keeps_current_value() -> TestResult {
    let seen = observation("rmm", &[(IdentityKey::Name, "web1")], &[("owner", "bob")]);
    let outcome = reconcile(&[with_owner("alice", "git")], &seen, &truth(&[("owner", "git")]))?;
    let merged = outcome.inventory.first().ok_or("empty")?;
    assert_eq!(merged.attributes.get("owner"), Some(&attribute("alice", "git")));
    assert_eq!(
        outcome.conflicts.first().map(|conflict| conflict.resolution),
        Some(Resolution::KeptCurrent)
    );
    Ok(())
}


#[test]
fn undeclared_attribute_keeps_current_and_is_undecided() -> TestResult {
    let existing = with_owner("alice", "git");
    let seen = observation("rmm", &[(IdentityKey::Name, "web1")], &[("owner", "bob")]);
    let outcome = reconcile(std::slice::from_ref(&existing), &seen, &TruthMap::new())?;
    assert_eq!(outcome.inventory, vec![existing.clone()]);
    assert_eq!(outcome.conflicts.first().map(|conflict| conflict.resolution), Some(Resolution::Undecided));
    let elsewhere = reconcile(&[existing], &seen, &truth(&[("owner", "cloud")]))?;
    assert_eq!(
        elsewhere.conflicts.first().map(|conflict| conflict.resolution),
        Some(Resolution::Undecided)
    );
    Ok(())
}


#[test]
fn same_value_and_same_source_do_not_conflict() -> TestResult {
    let existing = with_owner("alice", "git");
    let same = observation("rmm", &[(IdentityKey::Name, "web1")], &[("owner", "alice")]);
    let unchanged = reconcile(std::slice::from_ref(&existing), &same, &TruthMap::new())?;
    assert!(unchanged.conflicts.is_empty());
    assert_eq!(unchanged.inventory, vec![existing.clone()]);
    let update = observation("git", &[(IdentityKey::Name, "web1")], &[("owner", "carol")]);
    let updated = reconcile(&[existing], &update, &TruthMap::new())?;
    assert!(updated.conflicts.is_empty());
    let merged = updated.inventory.first().ok_or("empty")?;
    assert_eq!(merged.attributes.get("owner"), Some(&attribute("carol", "git")));
    Ok(())
}


#[test]
fn retired_or_destroyed_asset_reappears() -> TestResult {
    [Lifecycle::Retired, Lifecycle::Destroyed]
        .into_iter()
        .try_for_each(|lifecycle| -> TestResult {
            let inventory = vec![asset("a", &[(IdentityKey::Mac, "aa")], lifecycle)];
            let seen = observation("dhcp", &[(IdentityKey::Mac, "aa")], &[]);
            let outcome = reconcile(&inventory, &seen, &TruthMap::new())?;
            let expected = Event::Reappeared {
                asset: "a".to_string(),
                lifecycle,
            };
            assert_eq!(outcome.events, vec![expected]);
            assert_eq!(outcome.inventory.first().map(|found| found.lifecycle), Some(lifecycle));
            Ok(())
        })
}


#[test]
fn live_asset_does_not_reappear() -> TestResult {
    let inventory = vec![asset("a", &[(IdentityKey::Mac, "aa")], Lifecycle::InMaintenance)];
    let seen = observation("dhcp", &[(IdentityKey::Mac, "aa")], &[]);
    assert!(reconcile(&inventory, &seen, &TruthMap::new())?.events.is_empty());
    Ok(())
}


#[test]
fn lifecycle_is_ordered() -> TestResult {
    assert!(Lifecycle::Ordered < Lifecycle::InService);
    assert!(Lifecycle::InService < Lifecycle::InMaintenance);
    assert!(Lifecycle::InMaintenance < Lifecycle::Retired);
    assert!(Lifecycle::Retired < Lifecycle::Destroyed);
    Ok(())
}


#[test]
fn a_key_owned_by_another_asset_is_a_conflict_and_other_data_applies() -> TestResult {
    let inventory = vec![
        asset("a", &[(IdentityKey::SerialNumber, "S1")], Lifecycle::InService),
        asset("b", &[(IdentityKey::Mac, "M")], Lifecycle::InService),
    ];
    let seen = observation(
        "agent",
        &[(IdentityKey::SerialNumber, "S1"), (IdentityKey::Mac, "M"), (IdentityKey::Name, "web1")],
        &[("rack", "r1")],
    );
    let outcome = reconcile(&inventory, &seen, &TruthMap::new())?;
    let conflict = outcome.conflicts.first().ok_or("no conflict")?;
    assert_eq!(
        (conflict.asset.as_str(), conflict.attribute.as_str(), conflict.current.value.as_str()),
        ("a", "key:mac", "b")
    );
    assert_eq!(outcome.conflicts.len(), 1);
    let merged = outcome.inventory.iter().find(|item| item.id == "a").ok_or("no a")?;
    assert!(!merged.keys.contains_key(&IdentityKey::Mac));
    assert!(merged.keys.contains_key(&IdentityKey::Name));
    assert!(merged.attributes.contains_key("rack"));
    Ok(())
}
