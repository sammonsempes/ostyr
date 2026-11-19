use crate::model::{Edge, Graph, Node, NodeKind, Relation, MAX_EDGES, MAX_NODES};
use ad_posture::checks::{has_class, CLASS_COMPUTER, CLASS_GROUP, UAC_SERVER_TRUST};
use ad_posture::model::{Entry, Snapshot};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};


pub const MAX_MEMBER_OF_PER_NODE: usize = 1_000;


pub const MAX_LABEL_BYTES: usize = 64;


pub const LABEL_CUT_MARKER: &str = "...[cut]";


pub const NODE_ID_PREFIX: &str = "ad:";


const NO_BYTES: usize = 0;


pub const REPLACEMENT_CHAR: char = '?';


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


/// The graph, a display label per node id, what was left out, and whether a bound cut the result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdGraph {
    pub graph: Graph,
    pub labels: BTreeMap<String, String>,
    pub skipped: SkipCounts,
    pub truncated: bool,
}


pub struct Build<'snapshot> {
    pub nodes: Vec<Node>,
    pub labels: BTreeMap<String, String>,
    pub accepted: Vec<(String, &'snapshot Entry)>,
    pub skipped: SkipCounts,
    pub truncated: bool,
}


pub struct Linked {
    pub edges: Vec<Edge>,
    pub seen: BTreeSet<(String, String)>,
    pub skipped: SkipCounts,
    pub truncated: bool,
}


/// `ad:` and the hex SHA-256 of the lower-cased DN: bounded whatever the DN holds, and equal for DNs that differ only in case.
pub fn node_id(dn: &str) -> String {
    let digest: String = Sha256::digest(dn.to_lowercase().as_bytes())
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


/// A display name: only alphanumerics and printable ASCII survive, and a text over the bound is cut with a visible marker.
pub fn label_of(entry: &Entry) -> String {
    let source = entry.account.as_deref().unwrap_or(entry.dn.as_str());
    let clean: String = source
        .chars()
        .map(|found| {
            if found.is_alphanumeric() || found.is_ascii_graphic() || found == ' ' {
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


pub fn add_entry<'snapshot>(mut build: Build<'snapshot>, entry: &'snapshot Entry) -> Build<'snapshot> {
    let id = node_id(&entry.dn);
    if build.labels.contains_key(&id) {
        build.skipped.duplicate_dn += 1;
    } else if build.nodes.len() >= MAX_NODES {
        build.skipped.over_nodes += 1;
        build.truncated = true;
    } else {
        build.nodes.push(Node {
            id: id.clone(),
            kind: kind_of(entry),
            critical: false,
            entry_point: false,
        });
        build.labels.insert(id.clone(), label_of(entry));
        build.accepted.push((id, entry));
    }
    build
}


pub fn add_links(mut linked: Linked, source: &(String, &Entry), known: &BTreeMap<String, String>) -> Linked {
    let (from, entry) = source;
    if entry.member_of.len() > MAX_MEMBER_OF_PER_NODE {
        linked.skipped.over_member_cap += 1;
    } else if linked.edges.len() >= MAX_EDGES {
        linked.skipped.over_edges += entry.member_of.len();
        linked.truncated = true;
    } else {
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
            skipped: SkipCounts {
                unreadable: snapshot.unreadable.len(),
                ..SkipCounts::default()
            },
            truncated: !snapshot.bounds.is_empty(),
        },
        add_entry,
    );
    let linked = built.accepted.iter().fold(
        Linked {
            edges: Vec::new(),
            seen: BTreeSet::new(),
            skipped: built.skipped.clone(),
            truncated: built.truncated,
        },
        |state, source| add_links(state, source, &built.labels),
    );
    AdGraph {
        graph: Graph {
            nodes: built.nodes,
            edges: linked.edges,
        },
        labels: built.labels,
        skipped: linked.skipped,
        truncated: linked.truncated,
    }
}
