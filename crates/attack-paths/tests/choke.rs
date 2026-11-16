use attack_paths::bounds::validate_graph;
use attack_paths::choke::{choke_points, recommendations};
use attack_paths::model::{ChokePoint, Edge, EdgeRef, Graph, Limits, Node, NodeKind, Path, Recommendation, Relation};
use attack_paths::paths::paths_to_critical;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const TWO_PATHS: usize = 2;


const THREE_PATHS: usize = 3;


const DEPTH: usize = 8;


const CAP: usize = 100;


const EDGES_IN_AD_GRAPH: usize = 5;


fn route(ids: &[&str]) -> Path {
    Path {
        nodes: ids.iter().map(|id| id.to_string()).collect(),
    }
}


fn point(node: &str, paths_through: usize) -> ChokePoint {
    ChokePoint {
        node: node.to_string(),
        paths_through,
    }
}


fn advice(from: &str, to: &str, paths_closed: usize) -> Recommendation {
    Recommendation {
        edge: EdgeRef {
            from: from.to_string(),
            to: to.to_string(),
        },
        paths_closed,
    }
}


#[test]
fn choke_points_rank_by_count_then_id() -> TestResult {
    let paths = vec![
        route(&["ws1", "user", "group", "server", "dc"]),
        route(&["ws2", "user", "group", "server", "dc"]),
        route(&["ws3", "user", "dc"]),
        route(&["ws4", "other", "dc"]),
    ];
    assert_eq!(
        choke_points(&paths),
        vec![point("user", THREE_PATHS), point("group", TWO_PATHS), point("server", TWO_PATHS)]
    );
    Ok(())
}


#[test]
fn short_paths_have_no_interior_and_no_paths_no_points() -> TestResult {
    assert!(choke_points(&[route(&["a", "b"]), route(&["a", "b"]), route(&["a"]), route(&[])]).is_empty());
    assert!(choke_points(&[]).is_empty());
    assert!(recommendations(&[]).is_empty());
    Ok(())
}


#[test]
fn recommendations_rank_edges_by_paths_closed() -> TestResult {
    let paths = vec![
        route(&["ws1", "user", "group", "server", "dc"]),
        route(&["ws2", "user", "group", "server", "dc"]),
    ];
    let advised = recommendations(&paths);
    assert_eq!(advised.first(), Some(&advice("group", "server", TWO_PATHS)));
    assert_eq!(advised.len(), EDGES_IN_AD_GRAPH);
    assert_eq!(advised.last(), Some(&advice("ws2", "user", 1)));
    Ok(())
}


#[test]
fn ad_like_graph_end_to_end() -> TestResult {
    let entries = ["ws1", "ws2"];
    let graph = Graph {
        nodes: ["ws1", "ws2", "user", "group", "server", "dc"]
            .iter()
            .map(|id| Node {
                id: id.to_string(),
                kind: NodeKind::Server,
                critical: *id == "dc",
                entry_point: entries.contains(id),
            })
            .collect(),
        edges: [("ws1", "user"), ("ws2", "user"), ("user", "group"), ("group", "server"), ("server", "dc")]
            .iter()
            .map(|(from, to)| Edge {
                from: from.to_string(),
                to: to.to_string(),
                relation: Relation::HasSessionOn,
            })
            .collect(),
    };
    validate_graph(&graph)?;
    let found = paths_to_critical(
        &graph,
        Limits {
            max_depth: DEPTH,
            max_paths: CAP,
        },
    )?;
    assert_eq!(choke_points(&found.paths).first(), Some(&point("group", TWO_PATHS)));
    assert_eq!(recommendations(&found.paths).first(), Some(&advice("group", "server", TWO_PATHS)));
    Ok(())
}
