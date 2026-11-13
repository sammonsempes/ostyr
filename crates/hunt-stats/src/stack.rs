use crate::error::StatsError;
use crate::model::{KeyEntities, KeyReport, StackLimits};
use crate::types::{Grouped, Observation, RareReport};
use std::collections::{BTreeMap, BTreeSet};


/// Groups rows by key into distinct entities, skipping baseline keys; rows opening a key beyond `max_keys` are counted.
pub fn group_by_key(observations: &[Observation], baseline: &BTreeSet<String>, limits: &StackLimits) -> Result<Grouped, StatsError> {
    if observations.len() > limits.max_rows {
        Err(StatsError::TooManyRows {
            count: observations.len(),
            max: limits.max_rows,
        })
    } else {
        let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut dropped = 0;
        for (entity, key) in observations.iter().filter(|(_, key)| !baseline.contains(key)) {
            if groups.contains_key(key) || groups.len() < limits.max_keys {
                groups.entry(key.clone()).or_default().insert(entity.clone());
            } else {
                dropped += 1;
            }
        }
        Ok((groups, dropped))
    }
}


/// Keys sorted by distinct entity count then key, each with up to `max_examples` entities.
pub fn summarise(groups: BTreeMap<String, BTreeSet<String>>, max_entities: usize, max_examples: usize) -> Vec<KeyEntities> {
    let mut keys: Vec<KeyEntities> = groups
        .into_iter()
        .filter(|(_, entities)| entities.len() <= max_entities)
        .map(|(key, entities)| KeyEntities {
            key,
            entities: entities.len(),
            examples: entities.into_iter().take(max_examples).collect(),
        })
        .collect();
    keys.sort_by(|left, right| left.entities.cmp(&right.entities).then_with(|| left.key.cmp(&right.key)));
    keys
}


/// Keys seen on at most `max_entities` distinct entities: rarity counts entities, never rows.
pub fn rare_keys(observations: &[Observation], max_entities: usize, limits: &StackLimits) -> Result<RareReport, StatsError> {
    let (groups, rows_dropped) = group_by_key(observations, &BTreeSet::new(), limits)?;
    Ok(KeyReport {
        keys: summarise(groups, max_entities, limits.max_examples),
        rows_dropped,
    })
}
