//! Usage: `ad_paths <snapshot.json> [tags.yaml]`: users and workstations are the entry points; critical nodes are domain controllers and the tags.
use ad_posture::limits::Limits as SnapshotLimits;
use ad_posture::snapshot::read_snapshot;
use attack_paths::ad::{apply_ad_tags, graph_from_snapshot};
use attack_paths::choke::choke_points;
use attack_paths::model::{Limits, NodeKind, Tags, MAX_DEPTH, MAX_NODES, MAX_NODE_ID_BYTES, MAX_PATHS};
use attack_paths::paths::paths_to_critical;
use attack_paths::tags::load_tags;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::Path;


const SNAPSHOT_ARGUMENT: usize = 1;


const TAGS_ARGUMENT: usize = 2;


const SHOWN_POINTS: usize = 10;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<String> = std::env::args().collect();
    let snapshot = read_snapshot(
        File::open(arguments.get(SNAPSHOT_ARGUMENT).ok_or("missing snapshot.json")?)?,
        &SnapshotLimits::default(),
    )?;
    let mut built = graph_from_snapshot(&snapshot);
    built
        .graph
        .nodes
        .iter_mut()
        .for_each(|node| node.entry_point = matches!(node.kind, NodeKind::User | NodeKind::Workstation));
    let tags = match arguments.get(TAGS_ARGUMENT) {
        Some(path) => load_tags(Path::new(path))?,
        None => Tags::default(),
    };
    let skipped_tags = apply_ad_tags(&mut built, &tags)?;
    let found = paths_to_critical(
        &built.graph,
        Limits {
            max_depth: MAX_DEPTH,
            max_paths: MAX_PATHS,
        },
    )?;
    let label = |id: &String| {
        format!(
            "{} [{}]",
            built.labels.get(id).map_or(id.as_str(), String::as_str),
            built.digests.get(id).map_or("?", String::as_str)
        )
    };
    let mut out = stdout();
    writeln!(
        out,
        "SUMMARY nodes={} edges={} truncated={} incomplete_nodes={} duplicate_dns={} unreadable={} unknown_tags_skipped={} paths={} paths_truncated={} search_budget_reached={} removed_nodes={} skipped={:?}",
        built.graph.nodes.len(),
        built.graph.edges.len(),
        built.truncated,
        built.incomplete.len(),
        built.duplicates.len(),
        built.skipped.unreadable,
        skipped_tags.len(),
        found.paths.len(),
        found.truncated,
        found.budget_reached,
        built.removed_digests.len(),
        built.skipped
    )?;
    skipped_tags.iter().try_for_each(|tag| {
        let shown: String = tag.id.chars().take(MAX_NODE_ID_BYTES).collect();
        writeln!(out, "TAG_SKIPPED index={} id={shown:?}: names no node of the cut graph", tag.index)
    })?;
    built.incomplete.iter().try_for_each(|node| {
        writeln!(
            out,
            "INCOMPLETE {} {} field={} reason={} dropped={} over_limit={}: paths through it may be missing",
            node.digest,
            label(&node.id),
            node.field,
            node.reason,
            node.dropped,
            node.over_limit
        )
    })?;
    built
        .removed_digests
        .iter()
        .take(MAX_NODES)
        .try_for_each(|(_, digest)| writeln!(out, "REMOVED {digest} reason=over_nodes"))?;
    built
        .duplicates
        .iter()
        .try_for_each(|duplicate| writeln!(out, "DUPLICATE_DN kept={} dropped={}", duplicate.kept_digest, duplicate.dropped_digest))?;
    found
        .paths
        .iter()
        .try_for_each(|path| writeln!(out, "path {}", path.nodes.iter().map(label).collect::<Vec<_>>().join(" -> ")))?;
    choke_points(&found.paths)
        .iter()
        .take(SHOWN_POINTS)
        .try_for_each(|point| writeln!(out, "choke {} {}", label(&point.node), point.paths_through))?;
    Ok(())
}
