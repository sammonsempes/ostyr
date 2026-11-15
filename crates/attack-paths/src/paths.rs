use crate::bounds::{validate_graph, validate_limits};
use crate::model::{Graph, Limits, Path, PathSet};
use crate::types::{PathsResult, Search};
use hashbrown::HashSet;
use petgraph::algo::all_simple_paths_multi;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{BTreeMap, BTreeSet};


/// Simple paths from every entry point to every critical node, cut visibly: `truncated` is set when more than `max_paths` exist.
pub fn paths_to_critical(graph: &Graph, limits: Limits) -> PathsResult {
    validate_limits(limits)?;
    validate_graph(graph)?;
    let sorted: BTreeMap<&str, (bool, bool)> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), (node.entry_point, node.critical)))
        .collect();
    let mut search: Search = DiGraph::new();
    let index_of: BTreeMap<&str, NodeIndex> = sorted.keys().map(|id| (*id, search.add_node(*id))).collect();
    let edges: BTreeSet<(NodeIndex, NodeIndex)> = graph
        .edges
        .iter()
        .filter(|edge| edge.from != edge.to)
        .filter_map(|edge| index_of.get(edge.from.as_str()).zip(index_of.get(edge.to.as_str())))
        .map(|(from, to)| (*from, *to))
        .collect();
    edges.iter().rev().for_each(|(from, to)| {
        search.add_edge(*from, *to, ());
    });
    let flagged = |wanted_entry: bool| -> Vec<NodeIndex> {
        sorted
            .iter()
            .filter(|(_, flags)| if wanted_entry { flags.0 } else { flags.1 })
            .filter_map(|(id, _)| index_of.get(id).copied())
            .collect()
    };
    let entries = flagged(true);
    let critical = flagged(false);
    let mut found = entries.iter().fold(
        PathSet {
            paths: Vec::new(),
            truncated: false,
        },
        |mut state, entry| {
            let wanted: HashSet<NodeIndex> = critical.iter().copied().filter(|target| target != entry).collect();
            if !state.truncated && !wanted.is_empty() {
                let remaining = limits.max_paths - state.paths.len();
                let batch: Vec<Path> = all_simple_paths_multi::<Vec<NodeIndex>, _, _>(&search, *entry, &wanted, 0, Some(limits.max_depth - 1))
                    .filter(|nodes| nodes.len() <= limits.max_depth + 1)
                    .take(remaining + 1)
                    .map(|nodes| Path {
                        nodes: nodes.iter().map(|node| search[*node].to_string()).collect(),
                    })
                    .collect();
                state.truncated = batch.len() > remaining;
                state.paths.extend(batch.into_iter().take(remaining));
            }
            state
        },
    );
    found.paths.sort();
    Ok(found)
}
