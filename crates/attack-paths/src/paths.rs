use crate::bounds::{validate_graph, validate_limits};
use crate::model::{Graph, Limits, Path, PathSet, MAX_SEARCH_STEPS};
use crate::types::PathsResult;
use std::collections::{BTreeMap, BTreeSet, HashSet};


/// The pruned adjacency (children in ascending node order), the targets of the current entry and the depth bound of one walk.
pub struct Network<'graph> {
    pub adjacency: &'graph [Vec<usize>],
    pub targets: HashSet<usize>,
    pub max_depth: usize,
}


/// One node on the current path and the position of its next child.
pub struct Frame {
    pub node: usize,
    pub next: usize,
}


/// The state of one depth-first walk: the path, the nodes on it, how many targets it holds, the paths found and the steps spent.
pub struct Walk {
    pub stack: Vec<Frame>,
    pub on_path: HashSet<usize>,
    pub targets_on_path: usize,
    pub found: Vec<Vec<usize>>,
    pub steps: usize,
}


/// What one entry gave: the paths (one more than asked when the cap was passed), the steps spent and whether the budget ended the walk.
pub struct Outcome {
    pub found: Vec<Vec<usize>>,
    pub steps: usize,
    pub budget_reached: bool,
}


/// The nodes from which a target can be reached, found by a reverse walk (at most one round per node).
pub fn can_reach(parents: &[Vec<usize>], targets: &[usize]) -> HashSet<usize> {
    let (reach, _) = (0..=parents.len()).fold(
        (targets.iter().copied().collect::<HashSet<usize>>(), targets.to_vec()),
        |(mut reach, frontier), _| {
            let next: Vec<usize> = frontier
                .iter()
                .flat_map(|node| parents.get(*node).into_iter().flatten())
                .copied()
                .filter(|parent| reach.insert(*parent))
                .collect();
            (reach, next)
        },
    );
    reach
}


/// One examined edge: a child is skipped when it is on the path, yielded when it is a target within the depth, and expanded while a target is still unvisited.
pub fn advance(walk: &mut Walk, network: &Network) {
    walk.steps += 1;
    let child = walk.stack.last_mut().and_then(|frame| {
        let found = network.adjacency.get(frame.node).and_then(|children| children.get(frame.next)).copied();
        frame.next += 1;
        found
    });
    match child {
        None => {
            walk.stack.pop().iter().for_each(|frame| {
                walk.on_path.remove(&frame.node);
                walk.targets_on_path -= usize::from(network.targets.contains(&frame.node));
            });
        }
        Some(next) if walk.on_path.contains(&next) => {}
        Some(next) => {
            let is_target = network.targets.contains(&next);
            let depth = walk.stack.len();
            if is_target {
                walk.found
                    .push(walk.stack.iter().map(|frame| frame.node).chain(std::iter::once(next)).collect());
            }
            let unvisited = network.targets.len() - walk.targets_on_path - usize::from(is_target);
            if depth < network.max_depth && unvisited > 0 {
                walk.stack.push(Frame { node: next, next: 0 });
                walk.on_path.insert(next);
                walk.targets_on_path += usize::from(is_target);
            }
        }
    }
}


/// Simple paths from one entry, stopped when more than `remaining` were found or `budget` edges were examined.
pub fn walk_from(network: &Network, entry: usize, remaining: usize, budget: usize) -> Outcome {
    let mut walk = Walk {
        stack: vec![Frame { node: entry, next: 0 }],
        on_path: HashSet::from([entry]),
        targets_on_path: 0,
        found: Vec::new(),
        steps: 0,
    };
    while !walk.stack.is_empty() && walk.steps < budget.min(MAX_SEARCH_STEPS) && walk.found.len() <= remaining {
        advance(&mut walk, network);
    }
    let budget_reached = !walk.stack.is_empty() && walk.found.len() <= remaining;
    Outcome {
        found: walk.found,
        steps: walk.steps,
        budget_reached,
    }
}


/// Simple paths from every entry point to every critical node, cut visibly: `truncated` is set when more than `max_paths` exist or the step budget ended the search.
pub fn paths_to_critical(graph: &Graph, limits: Limits) -> PathsResult {
    paths_to_critical_with_budget(graph, limits, MAX_SEARCH_STEPS)
}


/// The same with an explicit step budget (edges examined, all entries together): `budget_reached` is set when it ended the search.
pub fn paths_to_critical_with_budget(graph: &Graph, limits: Limits, max_steps: usize) -> PathsResult {
    validate_limits(limits)?;
    validate_graph(graph)?;
    let sorted: BTreeMap<&str, (bool, bool)> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), (node.entry_point, node.critical)))
        .collect();
    let index_of: BTreeMap<&str, usize> = sorted.keys().enumerate().map(|(index, id)| (*id, index)).collect();
    let ids: Vec<&str> = sorted.keys().copied().collect();
    let edges: BTreeSet<(usize, usize)> = graph
        .edges
        .iter()
        .filter(|edge| edge.from != edge.to)
        .filter_map(|edge| index_of.get(edge.from.as_str()).zip(index_of.get(edge.to.as_str())))
        .map(|(from, to)| (*from, *to))
        .collect();
    let backwards: BTreeSet<(usize, usize)> = edges.iter().map(|(from, to)| (*to, *from)).collect();
    let flagged = |wanted_entry: bool| -> Vec<usize> {
        sorted
            .iter()
            .filter(|(_, flags)| if wanted_entry { flags.0 } else { flags.1 })
            .filter_map(|(id, _)| index_of.get(id).copied())
            .collect()
    };
    let entries = flagged(true);
    let critical = flagged(false);
    let parents: Vec<Vec<usize>> = (0..ids.len())
        .map(|to| backwards.range((to, 0)..=(to, usize::MAX)).map(|(_, from)| *from).collect())
        .collect();
    let reach = can_reach(&parents, &critical);
    let adjacency: Vec<Vec<usize>> = (0..ids.len())
        .map(|from| {
            edges
                .range((from, 0)..=(from, usize::MAX))
                .map(|(_, to)| *to)
                .filter(|to| reach.contains(to))
                .collect()
        })
        .collect();
    let (mut found, _) = entries.iter().fold(
        (
            PathSet {
                paths: Vec::new(),
                truncated: false,
                budget_reached: false,
                unsearched: Vec::new(),
            },
            max_steps,
        ),
        |(mut state, steps_left), entry| {
            let remaining = limits.max_paths - state.paths.len();
            let targets: HashSet<usize> = critical.iter().copied().filter(|target| target != entry).collect();
            let has_targets = !targets.is_empty();
            let idle = state.truncated || !has_targets;
            let network = Network {
                adjacency: &adjacency,
                targets,
                max_depth: limits.max_depth,
            };
            let walked = if idle {
                Outcome {
                    found: Vec::new(),
                    steps: 0,
                    budget_reached: false,
                }
            } else {
                walk_from(&network, *entry, remaining, steps_left)
            };
            state.truncated = state.truncated || walked.found.len() > remaining || walked.budget_reached;
            if has_targets && (walked.budget_reached || state.budget_reached) {
                state.unsearched.extend(ids.get(*entry).map(|id| id.to_string()));
            }
            state.budget_reached |= walked.budget_reached;
            state.paths.extend(walked.found.into_iter().take(remaining).map(|nodes| Path {
                nodes: nodes.iter().filter_map(|node| ids.get(*node)).map(|id| id.to_string()).collect(),
            }));
            (state, steps_left - walked.steps)
        },
    );
    found.paths.sort();
    Ok(found)
}
