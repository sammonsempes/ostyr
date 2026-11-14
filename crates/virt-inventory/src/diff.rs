use crate::error::InventoryError;
use crate::inventory::Inventory;
use crate::model::{InventoryDiff, ItemKey, ItemRef, Resource};
use crate::proxmox::item_key;
use std::collections::{BTreeMap, BTreeSet};


pub fn item_ref(resource: &Resource) -> ItemRef {
    ItemRef {
        kind: resource.kind,
        key: resource.key.clone(),
        name: resource.name.clone(),
        node: resource.node.clone(),
    }
}


/// Keyed by (kind, key). A current refused key is `unreadable`, never retired; a previous refused key absent from every current list is `retired_unreadable`.
pub fn diff_items(previous: &Inventory, current: &Inventory) -> InventoryDiff {
    let before = previous.items.iter().map(|item| (item_key(item), item)).collect::<BTreeMap<_, _>>();
    let after = current.items.iter().map(|item| (item_key(item), item)).collect::<BTreeMap<_, _>>();
    let refused_before = previous.skipped.refused_keys.iter().collect::<BTreeSet<&ItemKey>>();
    let refused_after = current.skipped.refused_keys.iter().collect::<BTreeSet<&ItemKey>>();
    InventoryDiff {
        created: after
            .iter()
            .filter(|(key, _)| !before.contains_key(*key))
            .map(|(_, item)| item_ref(item))
            .collect(),
        retired: before
            .iter()
            .filter(|(key, _)| !after.contains_key(*key) && !refused_after.contains(key))
            .map(|(_, item)| item_ref(item))
            .collect(),
        changed: after
            .iter()
            .filter(|(key, item)| before.get(*key).is_some_and(|old| old != *item))
            .map(|(_, item)| item_ref(item))
            .collect(),
        unreadable: refused_after.iter().map(|key| (*key).clone()).collect(),
        retired_unreadable: refused_before
            .iter()
            .filter(|key| !before.contains_key(**key) && !after.contains_key(**key) && !refused_after.contains(*key))
            .map(|key| (*key).clone())
            .collect(),
    }
}


/// Refused when the two inventories differ in tenant or cluster; a refused element is never retired.
pub fn diff(previous: &Inventory, current: &Inventory) -> Result<InventoryDiff, InventoryError> {
    if previous.tenant != current.tenant || previous.cluster != current.cluster {
        Err(InventoryError::ScopeMismatch)?;
    }
    Ok(diff_items(previous, current))
}
