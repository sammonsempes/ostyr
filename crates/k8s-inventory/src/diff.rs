use crate::error::InventoryError;
use crate::inventory::Inventory;
use crate::model::{InventoryDiff, ItemKind, ItemRef, NodeItem, PodItem};
use crate::parse::{node_uid, pod_uid};
use std::collections::BTreeMap;


pub fn pod_ref(pod: &PodItem) -> ItemRef {
    ItemRef {
        kind: ItemKind::Pod,
        uid: pod.uid.clone(),
        namespace: Some(pod.namespace.clone()),
        name: pod.name.clone(),
    }
}


pub fn node_ref(node: &NodeItem) -> ItemRef {
    ItemRef {
        kind: ItemKind::Node,
        uid: node.uid.clone(),
        namespace: None,
        name: node.name.clone(),
    }
}


/// Keyed by uid: created and retired items, and items whose uid is in both but whose content differs.
pub fn diff_items<Item: PartialEq>(
    previous: &[Item],
    current: &[Item],
    uid_of: fn(&Item) -> &str,
    ref_of: fn(&Item) -> ItemRef,
    out: &mut InventoryDiff,
) {
    let before = previous.iter().map(|item| (uid_of(item), item)).collect::<BTreeMap<_, _>>();
    let after = current.iter().map(|item| (uid_of(item), item)).collect::<BTreeMap<_, _>>();
    out.created
        .extend(after.iter().filter(|(uid, _)| !before.contains_key(*uid)).map(|(_, item)| ref_of(item)));
    out.retired
        .extend(before.iter().filter(|(uid, _)| !after.contains_key(*uid)).map(|(_, item)| ref_of(item)));
    out.changed.extend(
        after
            .iter()
            .filter(|(uid, item)| before.get(*uid).is_some_and(|old| old != *item))
            .map(|(_, item)| ref_of(item)),
    );
}


/// Refused when the two inventories differ in tenant or cluster; a recreated pod with the same name has a new uid: one retire plus one create.
pub fn diff(previous: &Inventory, current: &Inventory) -> Result<InventoryDiff, InventoryError> {
    if previous.tenant != current.tenant || previous.cluster != current.cluster {
        Err(InventoryError::ScopeMismatch)?;
    }
    let mut result = InventoryDiff::default();
    diff_items(&previous.pods, &current.pods, pod_uid, pod_ref, &mut result);
    diff_items(&previous.nodes, &current.nodes, node_uid, node_ref, &mut result);
    Ok(result)
}
