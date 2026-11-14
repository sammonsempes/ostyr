use crate::model::{Resource, ResourceKind};
use std::collections::BTreeMap;


pub const STATUS_UNKNOWN: &str = "unknown";


pub fn is_guest(resource: &Resource) -> bool {
    matches!(resource.kind, ResourceKind::Qemu | ResourceKind::Lxc)
}


pub fn is_unknown(resource: &Resource) -> bool {
    resource.status.as_deref() == Some(STATUS_UNKNOWN)
}


/// Nodes with at least one guest where every guest is `unknown`; one `unknown` guest among known ones stays a normal item.
pub fn degraded_nodes(items: &[Resource]) -> Vec<String> {
    items
        .iter()
        .filter(|resource| is_guest(resource))
        .fold(BTreeMap::<&str, bool>::new(), |mut nodes, resource| {
            let all_unknown = nodes.get(resource.node.as_str()).copied().unwrap_or(true) && is_unknown(resource);
            nodes.insert(resource.node.as_str(), all_unknown);
            nodes
        })
        .into_iter()
        .filter(|(_, all_unknown)| *all_unknown)
        .map(|(node, _)| node.to_owned())
        .collect()
}


/// Any item of a degraded node that answered `unknown` (its node and storage go `unknown` with pvestatd too).
pub fn is_degraded(degraded: &[String], resource: &Resource) -> bool {
    is_unknown(resource) && degraded.contains(&resource.node)
}
