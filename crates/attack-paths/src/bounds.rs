use crate::error::{GraphError, LimitsError};
use crate::model::{Graph, Limits, MAX_DEPTH, MAX_EDGES, MAX_NODES, MAX_NODE_ID_BYTES, MAX_PATHS};
use crate::types::{GraphResult, LimitsResult};
use std::collections::BTreeSet;


/// Refuses an oversized or malformed graph before any search: counts first, then each node and edge by index.
pub fn validate_graph(graph: &Graph) -> GraphResult {
    check_counts(graph)?;
    let known = graph.nodes.iter().enumerate().try_fold(BTreeSet::new(), |mut seen, (index, node)| {
        if !(1..=MAX_NODE_ID_BYTES).contains(&node.id.len()) {
            Err(GraphError::BadNodeId {
                index,
                max: MAX_NODE_ID_BYTES,
            })
        } else if seen.insert(node.id.as_str()) {
            Ok(seen)
        } else {
            Err(GraphError::DuplicateNode { index })
        }
    })?;
    graph.edges.iter().enumerate().try_for_each(|(index, edge)| {
        if [&edge.from, &edge.to].iter().all(|end| known.contains(end.as_str())) {
            Ok(())
        } else {
            Err(GraphError::UnknownNode { index })
        }
    })
}


fn check_counts(graph: &Graph) -> GraphResult {
    if graph.nodes.len() > MAX_NODES {
        Err(GraphError::TooManyNodes {
            count: graph.nodes.len(),
            max: MAX_NODES,
        })
    } else if graph.edges.len() > MAX_EDGES {
        Err(GraphError::TooManyEdges {
            count: graph.edges.len(),
            max: MAX_EDGES,
        })
    } else {
        Ok(())
    }
}


pub fn validate_limits(limits: Limits) -> LimitsResult {
    if !(1..=MAX_DEPTH).contains(&limits.max_depth) {
        Err(LimitsError::Depth {
            value: limits.max_depth,
            max: MAX_DEPTH,
        })
    } else if !(1..=MAX_PATHS).contains(&limits.max_paths) {
        Err(LimitsError::Paths {
            value: limits.max_paths,
            max: MAX_PATHS,
        })
    } else {
        Ok(())
    }
}
