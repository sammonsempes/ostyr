//! Usage: `ad_paths <snapshot.json> [tags.yaml]`: users and workstations are the entry points; critical nodes are domain controllers and the tags.
use ad_posture::limits::Limits as SnapshotLimits;
use ad_posture::snapshot::read_snapshot;
use attack_paths::ad::graph_from_snapshot;
use attack_paths::choke::choke_points;
use attack_paths::model::{Limits, NodeKind, Tags, MAX_DEPTH, MAX_PATHS};
use attack_paths::paths::paths_to_critical;
use attack_paths::tags::{apply_tags, apply_tags_lenient, load_tags};
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::Path;


const SNAPSHOT_ARGUMENT: usize = 1;


const TAGS_ARGUMENT: usize = 2;


const SHOWN_POINTS: usize = 10;


const SHOWN_NAMED: usize = 100;


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
    let unknown_tags = if built.truncated {
        apply_tags_lenient(&mut built.graph, &tags)
    } else {
        apply_tags(&mut built.graph, &tags)?;
        0
    };
    let found = paths_to_critical(
        &built.graph,
        Limits {
            max_depth: MAX_DEPTH,
            max_paths: MAX_PATHS,
        },
    )?;
    let label = |id: &String| built.labels.get(id).cloned().unwrap_or_else(|| id.clone());
    let mut out = stdout();
    writeln!(
        out,
        "nodes={} edges={} truncated={} paths={} paths_truncated={} skipped={:?}",
        built.graph.nodes.len(),
        built.graph.edges.len(),
        built.truncated,
        found.paths.len(),
        found.truncated,
        built.skipped
    )?;
    writeln!(out, "unknown_tags_skipped={unknown_tags}")?;
    built.incomplete.iter().take(SHOWN_NAMED).try_for_each(|node| {
        writeln!(
            out,
            "INCOMPLETE {} {} field={} dropped={} over_limit={}: paths through it may be missing",
            node.digest,
            label(&node.id),
            node.field,
            node.dropped,
            node.over_limit
        )
    })?;
    writeln!(out, "incomplete_nodes={} (first {SHOWN_NAMED} named)", built.incomplete.len())?;
    built
        .duplicates
        .iter()
        .take(SHOWN_NAMED)
        .try_for_each(|duplicate| writeln!(out, "DUPLICATE_DN kept={} dropped={}", duplicate.kept_digest, duplicate.dropped_digest))?;
    writeln!(out, "duplicate_dns={} (first {SHOWN_NAMED} named)", built.duplicates.len())?;
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
