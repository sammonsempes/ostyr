//! Version check, deduplication and ordering of parsed updates.

use crate::model::{Inventory, SkipReason, Update};
use crate::types::{SkipCounts, UpdateKey};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use vuln_match::model::Family;
use vuln_match::version::parse_version;


pub fn key_of(update: &Update) -> UpdateKey {
    (update.package.clone(), update.architecture.clone())
}


pub fn insert_preferring_security(map: &mut BTreeMap<UpdateKey, Update>, update: Update) {
    match map.entry(key_of(&update)) {
        Entry::Occupied(mut existing) => {
            if update.security && !existing.get().security {
                existing.insert(update);
            }
        }
        Entry::Vacant(slot) => {
            slot.insert(update);
        }
    }
}


pub fn versions_parse(family: Family, update: &Update) -> bool {
    parse_version(family, &update.candidate_version).is_ok()
        && update
            .installed_version
            .as_deref()
            .is_none_or(|installed| parse_version(family, installed).is_ok())
}


pub fn finish(family: Family, updates: Vec<Update>, mut skipped: SkipCounts) -> Inventory {
    let (valid, invalid): (Vec<Update>, Vec<Update>) = updates.into_iter().partition(|update| versions_parse(family, update));
    if !invalid.is_empty() {
        *skipped.entry(SkipReason::UnparsableVersion).or_insert(0) += invalid.len();
    }
    let mut unique = BTreeMap::new();
    valid.into_iter().for_each(|update| insert_preferring_security(&mut unique, update));
    Inventory {
        updates: unique.into_values().collect(),
        skipped,
    }
}
