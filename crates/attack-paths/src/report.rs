use crate::ad::{kind_name, AdGraph};
use crate::choke::choke_points;
use crate::model::{PathSet, MAX_NODES, MAX_NODE_ID_BYTES};
use crate::tags::SkippedTag;
use std::io::{Result as IoResult, Write};


/// The printed label of a node: its clean label and its digest.
pub fn label_of_node(built: &AdGraph, id: &String) -> String {
    format!(
        "{} [{}]",
        built.labels.get(id).map_or(id.as_str(), String::as_str),
        built.digests.get(id).map_or("?", String::as_str)
    )
}


/// The SUMMARY line, then every line that says a result is incomplete (tags, INCOMPLETE, REMOVED, UNSEARCHED, DUPLICATE_DN), then the paths and the choke points.
pub fn write_report<Sink: Write>(out: &mut Sink, built: &AdGraph, found: &PathSet, skipped_tags: &[SkippedTag], shown_points: usize) -> IoResult<()> {
    write_summary(out, built, found, skipped_tags)?;
    write_gaps(out, built, found, skipped_tags)?;
    write_paths(out, built, found, shown_points)
}


fn write_summary<Sink: Write>(out: &mut Sink, built: &AdGraph, found: &PathSet, skipped_tags: &[SkippedTag]) -> IoResult<()> {
    writeln!(
        out,
        "SUMMARY nodes={} edges={} truncated={} incomplete_nodes={} duplicate_dns={} unreadable={} unknown_tags_skipped={} paths={} paths_truncated={} search_budget_reached={} unsearched_entries={} removed_nodes={} skipped={:?}",
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
        found.unsearched.len(),
        built.removed_digests.len(),
        built.skipped
    )
}


fn write_gaps<Sink: Write>(out: &mut Sink, built: &AdGraph, found: &PathSet, skipped_tags: &[SkippedTag]) -> IoResult<()> {
    skipped_tags.iter().try_for_each(|tag| {
        let shown: String = tag.id.chars().take(MAX_NODE_ID_BYTES).collect();
        writeln!(out, "TAG_SKIPPED index={} id={shown:?}: names no node of the cut graph", tag.index)
    })?;
    built.incomplete.iter().try_for_each(|node| {
        writeln!(
            out,
            "INCOMPLETE {} {} field={} reason={} dropped={} over_limit={}: paths through it may be missing",
            node.digest,
            label_of_node(built, &node.id),
            node.field,
            node.reason,
            node.dropped,
            node.over_limit
        )
    })?;
    built.removed_digests.iter().take(MAX_NODES).try_for_each(|(id, digest)| {
        let kind = built.removed_kinds.get(id).map_or("?", |kind| kind_name(*kind));
        writeln!(out, "REMOVED {digest} kind={kind} reason=over_nodes")
    })?;
    found.unsearched.iter().try_for_each(|entry| {
        writeln!(
            out,
            "UNSEARCHED {} {} reason={}: a bound ended the search before this entry was complete",
            built.digests.get(&entry.id).map_or("?", String::as_str),
            label_of_node(built, &entry.id),
            entry.reason
        )
    })?;
    built
        .duplicates
        .iter()
        .try_for_each(|duplicate| writeln!(out, "DUPLICATE_DN kept={} dropped={}", duplicate.kept_digest, duplicate.dropped_digest))
}


fn write_paths<Sink: Write>(out: &mut Sink, built: &AdGraph, found: &PathSet, shown_points: usize) -> IoResult<()> {
    found.paths.iter().try_for_each(|path| {
        writeln!(
            out,
            "path {}",
            path.nodes.iter().map(|id| label_of_node(built, id)).collect::<Vec<_>>().join(" -> ")
        )
    })?;
    choke_points(&found.paths)
        .iter()
        .take(shown_points)
        .try_for_each(|point| writeln!(out, "choke {} {}", label_of_node(built, &point.node), point.paths_through))
}
