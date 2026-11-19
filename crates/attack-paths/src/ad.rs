use crate::error::TagsError;
use crate::model::{Edge, Graph, Node, NodeKind, Relation, Tags, MAX_EDGES, MAX_NODES};
use crate::tags::{apply_tags, apply_tags_lenient, SkippedTag};
use ad_posture::checks::{has_class, CLASS_COMPUTER, CLASS_GROUP, UAC_SERVER_TRUST};
use ad_posture::model::{Entry, Snapshot};
use ad_posture::snapshot::digest_prefix;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};


pub const MAX_MEMBER_OF_PER_NODE: usize = 1_000;


pub const MAX_LABEL_BYTES: usize = 64;


pub const LABEL_CUT_MARKER: &str = "...[cut]";


pub const NODE_ID_PREFIX: &str = "ad:";


const NO_BYTES: usize = 0;


pub const REPLACEMENT_CHAR: char = '?';


pub const LABEL_PUNCTUATION: &str = " ._$-";


pub const FIELD_MEMBER_OF: &str = "memberOf";


pub const FIELD_OBJECT_CLASS: &str = "objectClass";


pub const REASON_GAP: &str = "gap";


pub const REASON_OVER_MEMBER_CAP: &str = "over_member_cap";


pub const REASON_UNREADABLE_TARGET: &str = "unreadable_target";


/// Entries and values left out of the graph, by reason.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkipCounts {
    pub unreadable: usize,
    pub duplicate_dn: usize,
    pub unknown_target: usize,
    pub over_member_cap: usize,
    pub over_nodes: usize,
    pub over_edges: usize,
    pub repeated_edge: usize,
}


/// A node whose `memberOf` or `objectClass` values could not be kept in full (gap, over the edge cap, unreadable target): its edges or kind may be missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompleteNode {
    pub id: String,
    pub digest: String,
    pub field: &'static str,
    pub reason: &'static str,
    pub dropped: usize,
    pub over_limit: bool,
}


/// A DN that repeats an earlier one: the first is kept, both are named by the digest of their exact text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateDn {
    pub kept_digest: String,
    pub dropped_digest: String,
}


/// The graph, a display label per node id, what was left out, and whether a bound cut the result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdGraph {
    pub graph: Graph,
    pub labels: BTreeMap<String, String>,
    pub skipped: SkipCounts,
    pub truncated: bool,
    pub nodes_removed: bool,
    pub digests: BTreeMap<String, String>,
    pub incomplete: Vec<IncompleteNode>,
    pub duplicates: Vec<DuplicateDn>,
}


pub struct Build<'snapshot> {
    pub nodes: Vec<Node>,
    pub labels: BTreeMap<String, String>,
    pub accepted: Vec<(String, &'snapshot Entry)>,
    pub first_dn: BTreeMap<String, &'snapshot str>,
    pub skipped: SkipCounts,
    pub truncated: bool,
    pub incomplete: Vec<IncompleteNode>,
    pub duplicates: Vec<DuplicateDn>,
}


pub struct Linked {
    pub edges: Vec<Edge>,
    pub seen: BTreeSet<(String, String)>,
    pub skipped: SkipCounts,
    pub truncated: bool,
    pub incomplete: Vec<IncompleteNode>,
}


/// `ad:` and the hex SHA-256 of the ASCII-lower-cased DN: bounded whatever the DN holds; a non-ASCII character is never case-folded, so no look-alike merges.
pub fn node_id(dn: &str) -> String {
    let digest: String = Sha256::digest(dn.to_ascii_lowercase().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{NODE_ID_PREFIX}{digest}")
}


pub fn kind_of(entry: &Entry) -> NodeKind {
    if has_class(entry, CLASS_GROUP) {
        NodeKind::Group
    } else if has_class(entry, CLASS_COMPUTER) && entry.uac & UAC_SERVER_TRUST != 0 {
        NodeKind::DomainController
    } else if has_class(entry, CLASS_COMPUTER) {
        NodeKind::Workstation
    } else {
        NodeKind::User
    }
}


/// A display name: only `[A-Za-z0-9 ._$-]` survive, and a text over the bound is cut with a visible marker.
pub fn label_of(entry: &Entry) -> String {
    let source = entry.account.as_deref().unwrap_or(entry.dn.as_str());
    let clean: String = source
        .chars()
        .map(|found| {
            if found.is_ascii_alphanumeric() || LABEL_PUNCTUATION.contains(found) {
                found
            } else {
                REPLACEMENT_CHAR
            }
        })
        .collect();
    if clean.len() <= MAX_LABEL_BYTES {
        clean
    } else {
        let kept: String = clean
            .chars()
            .scan(NO_BYTES, |used, found| {
                *used += found.len_utf8();
                (*used <= MAX_LABEL_BYTES).then_some(found)
            })
            .collect();
        format!("{kept}{LABEL_CUT_MARKER}")
    }
}


pub fn incomplete_of(id: &str, entry: &Entry) -> Vec<IncompleteNode> {
    entry
        .gaps
        .iter()
        .filter(|gap| gap.field == FIELD_MEMBER_OF || gap.field == FIELD_OBJECT_CLASS)
        .map(|gap| IncompleteNode {
            id: id.to_string(),
            digest: digest_prefix(&entry.dn),
            field: gap.field,
            reason: REASON_GAP,
            dropped: gap.dropped,
            over_limit: gap.over_limit,
        })
        .collect()
}


pub fn add_entry<'snapshot>(mut build: Build<'snapshot>, entry: &'snapshot Entry) -> Build<'snapshot> {
    let id = node_id(&entry.dn);
    if let Some(first) = build.first_dn.get(&id) {
        build.skipped.duplicate_dn += 1;
        build.truncated = true;
        build.duplicates.push(DuplicateDn {
            kept_digest: digest_prefix(first),
            dropped_digest: digest_prefix(&entry.dn),
        });
    } else if build.nodes.len() >= MAX_NODES {
        build.skipped.over_nodes += 1;
        build.truncated = true;
    } else {
        let gaps = incomplete_of(&id, entry);
        build.truncated = build.truncated || !gaps.is_empty();
        build.incomplete.extend(gaps);
        build.nodes.push(Node {
            id: id.clone(),
            kind: kind_of(entry),
            critical: false,
            entry_point: false,
        });
        build.labels.insert(id.clone(), label_of(entry));
        build.first_dn.insert(id.clone(), entry.dn.as_str());
        build.accepted.push((id, entry));
    }
    build
}


/// The digest ad-posture gives an unreadable entry: the SHA-256 prefix of the DN as a JSON string.
pub fn unreadable_digest(dn: &str) -> String {
    digest_prefix(&serde_json::Value::String(dn.to_string()).to_string())
}


pub fn incomplete_link(from: &str, entry: &Entry, reason: &'static str, dropped: usize) -> IncompleteNode {
    IncompleteNode {
        id: from.to_string(),
        digest: digest_prefix(&entry.dn),
        field: FIELD_MEMBER_OF,
        reason,
        dropped,
        over_limit: reason == REASON_OVER_MEMBER_CAP,
    }
}


pub fn add_links(mut linked: Linked, source: &(String, &Entry), known: &BTreeMap<String, String>, unreadable: &BTreeSet<&str>) -> Linked {
    let (from, entry) = source;
    if entry.member_of.len() > MAX_MEMBER_OF_PER_NODE {
        linked.skipped.over_member_cap += 1;
        linked.truncated = true;
        linked
            .incomplete
            .push(incomplete_link(from, entry, REASON_OVER_MEMBER_CAP, entry.member_of.len()));
    } else if linked.edges.len() >= MAX_EDGES {
        linked.skipped.over_edges += entry.member_of.len();
        linked.truncated = true;
    } else {
        let lost = entry
            .member_of
            .iter()
            .filter(|group| !known.contains_key(&node_id(group)) && unreadable.contains(unreadable_digest(group).as_str()))
            .count();
        if lost > 0 {
            linked.incomplete.push(incomplete_link(from, entry, REASON_UNREADABLE_TARGET, lost));
        }
        entry.member_of.iter().for_each(|group| {
            let to = node_id(group);
            if !known.contains_key(&to) {
                linked.skipped.unknown_target += 1;
            } else if linked.edges.len() >= MAX_EDGES {
                linked.skipped.over_edges += 1;
                linked.truncated = true;
            } else if *from == to || !linked.seen.insert((from.clone(), to.clone())) {
                linked.skipped.repeated_edge += 1;
            } else {
                linked.edges.push(Edge {
                    from: from.clone(),
                    to,
                    relation: Relation::MemberOf,
                });
            }
        });
    }
    linked
}


/// The membership graph of a snapshot: one node per entry, one `MemberOf` edge per `memberOf` value naming another entry; bounded, never empty on a hostile object.
pub fn graph_from_snapshot(snapshot: &Snapshot) -> AdGraph {
    let built = snapshot.entries.iter().fold(
        Build {
            nodes: Vec::new(),
            labels: BTreeMap::new(),
            accepted: Vec::new(),
            first_dn: BTreeMap::new(),
            skipped: SkipCounts {
                unreadable: snapshot.unreadable.len(),
                ..SkipCounts::default()
            },
            truncated: !snapshot.bounds.is_empty() || !snapshot.unreadable.is_empty(),
            incomplete: Vec::new(),
            duplicates: Vec::new(),
        },
        add_entry,
    );
    let unreadable: BTreeSet<&str> = snapshot.unreadable.iter().map(|lost| lost.dn_digest.as_str()).collect();
    let linked = built.accepted.iter().fold(
        Linked {
            edges: Vec::new(),
            seen: BTreeSet::new(),
            skipped: built.skipped.clone(),
            truncated: built.truncated,
            incomplete: Vec::new(),
        },
        |state, source| add_links(state, source, &built.labels, &unreadable),
    );
    let nodes_removed =
        !snapshot.unreadable.is_empty() || !snapshot.bounds.is_empty() || built.skipped.over_nodes > 0 || built.skipped.duplicate_dn > 0;
    let digests: BTreeMap<String, String> = built.first_dn.iter().map(|(id, dn)| (id.clone(), digest_prefix(dn))).collect();
    let truncated = linked.truncated || !linked.incomplete.is_empty();
    let incomplete: Vec<IncompleteNode> = built.incomplete.iter().cloned().chain(linked.incomplete.iter().cloned()).collect();
    AdGraph {
        graph: Graph {
            nodes: built.nodes,
            edges: linked.edges,
        },
        labels: built.labels,
        skipped: linked.skipped,
        truncated,
        nodes_removed,
        digests,
        incomplete,
        duplicates: built.duplicates,
    }
}


/// Marks the tags: lenient only when a node was really removed (an attacker can set `truncated` with one bad value), else a wrong tag is an error.
pub fn apply_ad_tags(built: &mut AdGraph, tags: &Tags) -> Result<Vec<SkippedTag>, TagsError> {
    if built.nodes_removed {
        Ok(apply_tags_lenient(&mut built.graph, tags))
    } else {
        apply_tags(&mut built.graph, tags).map(|()| Vec::new())
    }
}
