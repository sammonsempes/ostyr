use crate::error::TagsError;
use crate::model::{Graph, NodeKind, Tags, MAX_TAGS};
use crate::types::{ApplyResult, TagsResult};
use core_config::load::load_file;
use std::collections::BTreeSet;
use std::path::Path;


pub fn kind_is_critical(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::DomainController | NodeKind::AdCs | NodeKind::BackupServer | NodeKind::Hypervisor | NodeKind::SecretsVault
    )
}


/// Strict manual tag file: an unknown key is refused and the list is bounded.
pub fn load_tags(path: &Path) -> TagsResult {
    let tags: Tags = load_file(path)?;
    check_tags(tags)
}


pub fn check_tags(tags: Tags) -> TagsResult {
    if tags.critical.len() > MAX_TAGS {
        Err(TagsError::TooMany {
            count: tags.critical.len(),
            max: MAX_TAGS,
        })
    } else {
        Ok(tags)
    }
}


/// Marks every node of a critical kind, and every node the manual tags name, as critical; a tag naming no node is refused.
pub fn apply_tags(graph: &mut Graph, tags: &Tags) -> ApplyResult {
    let known = known_ids(graph);
    tags.critical.iter().enumerate().try_for_each(|(index, tagged)| {
        if known.contains(tagged.as_str()) {
            Ok(())
        } else {
            Err(TagsError::UnknownNode { index })
        }
    })?;
    mark_critical(graph, tags);
    Ok(())
}


/// A tag naming a node the graph does not hold: its position in the file and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedTag {
    pub index: usize,
    pub id: String,
}


/// Same marking for a graph where a node was removed, so a tagged node may be the one that was cut: an unknown tag is skipped and returned.
pub fn apply_tags_lenient(graph: &mut Graph, tags: &Tags) -> Vec<SkippedTag> {
    let known = known_ids(graph);
    let skipped: Vec<SkippedTag> = tags
        .critical
        .iter()
        .enumerate()
        .filter(|(_, tagged)| !known.contains(tagged.as_str()))
        .map(|(index, tagged)| SkippedTag { index, id: tagged.clone() })
        .collect();
    mark_critical(graph, tags);
    skipped
}


pub fn known_ids(graph: &Graph) -> BTreeSet<String> {
    graph.nodes.iter().map(|node| node.id.clone()).collect()
}


pub fn mark_critical(graph: &mut Graph, tags: &Tags) {
    let manual: BTreeSet<&str> = tags.critical.iter().map(String::as_str).collect();
    let marked: BTreeSet<String> = graph
        .nodes
        .iter()
        .filter(|node| kind_is_critical(node.kind) || manual.contains(node.id.as_str()))
        .map(|node| node.id.clone())
        .collect();
    graph
        .nodes
        .iter_mut()
        .for_each(|node| node.critical = node.critical || marked.contains(&node.id));
}
