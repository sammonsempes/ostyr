use crate::error::InventoryError;
use crate::inventory::Inventory;
use crate::model::{InventoryDiff, ItemKind, ItemRef, NodeItem, PodItem, Skipped, UnreadableRef};
use crate::parse::{node_uid, pod_uid};
use std::collections::{BTreeMap, BTreeSet};


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


pub fn unreadable_ref(kind: ItemKind, uid: &str) -> UnreadableRef {
    UnreadableRef { kind, uid: uid.to_owned() }
}


/// Keyed by uid. A current refused uid is `unreadable`, never retired; a previous refused uid absent from every current list is `retired_unreadable`.
pub fn diff_items<Item: PartialEq>(
    previous: (&[Item], &Skipped),
    current: (&[Item], &Skipped),
    kind: ItemKind,
    uid_of: fn(&Item) -> &str,
    ref_of: fn(&Item) -> ItemRef,
) -> InventoryDiff {
    let before = previous.0.iter().map(|item| (uid_of(item), item)).collect::<BTreeMap<_, _>>();
    let after = current.0.iter().map(|item| (uid_of(item), item)).collect::<BTreeMap<_, _>>();
    let refused_before = previous.1.refused_uids.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let refused_after = current.1.refused_uids.iter().map(String::as_str).collect::<BTreeSet<_>>();
    InventoryDiff {
        created: after
            .iter()
            .filter(|(uid, _)| !before.contains_key(*uid))
            .map(|(_, item)| ref_of(item))
            .collect(),
        retired: before
            .iter()
            .filter(|(uid, _)| !after.contains_key(*uid) && !refused_after.contains(*uid))
            .map(|(_, item)| ref_of(item))
            .collect(),
        changed: after
            .iter()
            .filter(|(uid, item)| before.get(*uid).is_some_and(|old| old != *item))
            .map(|(_, item)| ref_of(item))
            .collect(),
        unreadable: refused_after.iter().map(|uid| unreadable_ref(kind, uid)).collect(),
        retired_unreadable: refused_before
            .iter()
            .filter(|uid| !before.contains_key(*uid) && !after.contains_key(*uid) && !refused_after.contains(*uid))
            .map(|uid| unreadable_ref(kind, uid))
            .collect(),
    }
}


pub fn merge_diff(first: InventoryDiff, second: InventoryDiff) -> InventoryDiff {
    InventoryDiff {
        created: [first.created, second.created].concat(),
        retired: [first.retired, second.retired].concat(),
        changed: [first.changed, second.changed].concat(),
        unreadable: [first.unreadable, second.unreadable].concat(),
        retired_unreadable: [first.retired_unreadable, second.retired_unreadable].concat(),
    }
}


/// Refused when the two inventories differ in tenant or cluster; a recreated pod with the same name has a new uid: one retire plus one create.
pub fn diff(previous: &Inventory, current: &Inventory) -> Result<InventoryDiff, InventoryError> {
    if previous.tenant != current.tenant || previous.cluster != current.cluster {
        Err(InventoryError::ScopeMismatch)?;
    }
    Ok(merge_diff(
        diff_items(
            (&previous.pods, &previous.skipped_pods),
            (&current.pods, &current.skipped_pods),
            ItemKind::Pod,
            pod_uid,
            pod_ref,
        ),
        diff_items(
            (&previous.nodes, &previous.skipped_nodes),
            (&current.nodes, &current.skipped_nodes),
            ItemKind::Node,
            node_uid,
            node_ref,
        ),
    ))
}
