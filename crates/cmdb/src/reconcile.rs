use crate::error::CmdbError;
use crate::model::{Asset, Attribute, Conflict, Event, IdentityKey, Lifecycle, Observation, Outcome, Resolution};
use crate::summary::MAX_ID_BYTES;
use crate::types::TruthMap;


pub const RESERVED_SOURCE: &str = "cmdb";


pub const RESERVED_ATTRIBUTE_PREFIX: &str = "key:";


pub fn is_reserved_source(source: &str) -> bool {
    source.trim().eq_ignore_ascii_case(RESERVED_SOURCE)
}


pub fn is_reserved_attribute(name: &str) -> bool {
    name.trim_start().to_ascii_lowercase().starts_with(RESERVED_ATTRIBUTE_PREFIX)
}


pub const MAX_VALUE_BYTES: usize = 4_096;


pub const MAX_ATTRIBUTE_NAME_BYTES: usize = 256;


/// Refuses text over `cap` bytes or holding a control character (NUL and ANSI escapes included); the error names the field, never the value.
pub fn check_text(field: &'static str, text: &str, cap: usize) -> Result<(), CmdbError> {
    match (text.len() > cap, text.chars().any(char::is_control)) {
        (true, _) => Err(CmdbError::FieldTooLong { field, limit: cap }),
        (false, true) => Err(CmdbError::ControlCharacter { field }),
        (false, false) => Ok(()),
    }
}


pub fn check_reserved(observation: &Observation) -> Result<(), CmdbError> {
    let attribute_reserved = observation.attributes.keys().any(|name| is_reserved_attribute(name));
    match (is_reserved_source(&observation.source), attribute_reserved) {
        (true, _) => Err(CmdbError::ReservedName { field: "source" }),
        (false, true) => Err(CmdbError::ReservedName { field: "attributes" }),
        (false, false) => Ok(()),
    }
}


/// Refuses the source `cmdb`, attribute names starting `key:`, and a source, key value, derived asset id, attribute name or value over its cap or with a control character.
pub fn check_observation(observation: &Observation) -> Result<(), CmdbError> {
    check_reserved(observation)?;
    check_text("source", &observation.source, MAX_VALUE_BYTES)?;
    observation
        .keys
        .values()
        .try_for_each(|value| check_text("keys", value, MAX_VALUE_BYTES))?;
    observation
        .attributes
        .keys()
        .try_for_each(|name| check_text("attribute name", name, MAX_ATTRIBUTE_NAME_BYTES))?;
    observation
        .attributes
        .values()
        .try_for_each(|value| check_text("attribute value", value, MAX_VALUE_BYTES))?;
    observation
        .keys
        .iter()
        .next()
        .map_or(Ok(()), |(key, value)| check_text("asset id", &format!("{key}:{value}"), MAX_ID_BYTES))
}


/// First asset sharing a key value with the observation, trying the keys from the strongest to the weakest.
pub fn find_asset<'a>(inventory: &'a [Asset], observation: &Observation) -> Option<&'a Asset> {
    observation
        .keys
        .iter()
        .find_map(|(key, value)| inventory.iter().find(|asset| asset.keys.get(key) == Some(value)))
}


pub fn new_asset(observation: &Observation) -> Result<Asset, CmdbError> {
    let id = observation
        .keys
        .iter()
        .next()
        .map(|(key, value)| format!("{key}:{value}"))
        .ok_or_else(|| CmdbError::NoIdentity {
            source_name: observation.source.clone(),
        })?;
    Ok(Asset {
        id,
        kind: observation.kind,
        lifecycle: Lifecycle::InService,
        keys: observation.keys.clone(),
        attributes: Default::default(),
    })
}


pub fn resolve(declared: Option<&String>, current_source: &str, observed_source: &str) -> Resolution {
    match declared {
        Some(truth) if truth == observed_source => Resolution::TookObserved,
        Some(truth) if truth == current_source => Resolution::KeptCurrent,
        _ => Resolution::Undecided,
    }
}


pub fn apply_attribute(asset: &mut Asset, conflicts: &mut Vec<Conflict>, observation: &Observation, truth: &TruthMap, name: &str, value: &str) {
    let observed = Attribute {
        value: value.to_string(),
        source: observation.source.clone(),
    };
    match asset.attributes.get(name).cloned() {
        Some(current) if current.value == observed.value => (),
        Some(current) if current.source == observed.source => {
            asset.attributes.insert(name.to_string(), observed);
        }
        Some(current) => {
            let resolution = resolve(truth.get(name), &current.source, &observed.source);
            if resolution == Resolution::TookObserved {
                asset.attributes.insert(name.to_string(), observed.clone());
            }
            conflicts.push(Conflict {
                asset: asset.id.clone(),
                attribute: name.to_string(),
                current,
                observed,
                resolution,
            });
        }
        None => {
            asset.attributes.insert(name.to_string(), observed);
        }
    }
}


/// Adds a key the asset lacks, unless another asset of the inventory owns it: then a `key:<name>` conflict names both assets and the key stays put.
pub fn merge_key(asset: &mut Asset, conflicts: &mut Vec<Conflict>, inventory: &[Asset], observation: &Observation, key: IdentityKey, value: &str) {
    let owner = inventory
        .iter()
        .find(|other| other.id != asset.id && other.keys.get(&key).is_some_and(|owned| owned == value));
    match (asset.keys.contains_key(&key), owner) {
        (true, _) => (),
        (false, None) => {
            asset.keys.insert(key, value.to_string());
        }
        (false, Some(other)) => conflicts.push(Conflict {
            asset: asset.id.clone(),
            attribute: format!("key:{key}"),
            current: Attribute {
                value: other.id.clone(),
                source: RESERVED_SOURCE.to_string(),
            },
            observed: Attribute {
                value: value.to_string(),
                source: observation.source.clone(),
            },
            resolution: Resolution::KeptCurrent,
        }),
    }
}


/// Pure: returns the next inventory, the conflict log entries and the events; the input is never modified.
pub fn reconcile(inventory: &[Asset], observation: &Observation, truth: &TruthMap) -> Result<Outcome, CmdbError> {
    check_observation(observation)?;
    let matched = find_asset(inventory, observation).cloned();
    let created = matched.is_none();
    let mut asset = matched.map_or_else(|| new_asset(observation), Ok)?;
    let collides = created && inventory.iter().any(|existing| existing.id == asset.id);
    collides
        .then_some(())
        .map_or(Ok(()), |()| Err(CmdbError::IdCollision { id: asset.id.clone() }))?;
    let reappeared = !created && matches!(asset.lifecycle, Lifecycle::Retired | Lifecycle::Destroyed);
    let mut conflicts = Vec::new();
    observation
        .keys
        .iter()
        .for_each(|(key, value)| merge_key(&mut asset, &mut conflicts, inventory, observation, *key, value));
    observation
        .attributes
        .iter()
        .for_each(|(name, value)| apply_attribute(&mut asset, &mut conflicts, observation, truth, name, value));
    let events = created
        .then(|| Event::Created { asset: asset.id.clone() })
        .into_iter()
        .chain(reappeared.then(|| Event::Reappeared {
            asset: asset.id.clone(),
            lifecycle: asset.lifecycle,
        }))
        .collect();
    let replaced = inventory
        .iter()
        .map(|existing| if existing.id == asset.id { asset.clone() } else { existing.clone() });
    let inventory_after = replaced.chain(created.then(|| asset.clone())).collect();
    Ok(Outcome {
        inventory: inventory_after,
        conflicts,
        events,
    })
}
