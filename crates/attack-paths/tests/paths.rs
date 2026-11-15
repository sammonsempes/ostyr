use attack_paths::bounds::validate_graph;
use attack_paths::error::{GraphError, LimitsError, PathsError};
use attack_paths::model::{Edge, Graph, Limits, Node, NodeKind, Path, Relation, MAX_DEPTH, MAX_PATHS};
use attack_paths::paths::paths_to_critical;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const LADDER_LAYERS: usize = 12;


const LADDER_CAP: usize = 100;


const LADDER_DEPTH: usize = 16;


const LADDER_PATHS: usize = 4096;


const CHAIN_LENGTH: usize = 4;


const TWO_PATHS: usize = 2;


fn node(id: &str, kind: NodeKind, critical: bool, entry_point: bool) -> Node {
    Node {
        id: id.to_string(),
        kind,
        critical,
        entry_point,
    }
}


fn link(from: &str, to: &str) -> Edge {
    Edge {
        from: from.to_string(),
        to: to.to_string(),
        relation: Relation::AdminTo,
    }
}


fn route(ids: &[&str]) -> Path {
    Path {
        nodes: ids.iter().map(|id| id.to_string()).collect(),
    }
}


fn limits(max_depth: usize, max_paths: usize) -> Limits {
    Limits { max_depth, max_paths }
}


fn ad_graph() -> Graph {
    Graph {
        nodes: vec![
            node("ws1", NodeKind::Workstation, false, true),
            node("ws2", NodeKind::Workstation, false, true),
            node("user", NodeKind::User, false, false),
            node("group", NodeKind::Group, false, false),
            node("server", NodeKind::Server, false, false),
            node("dc", NodeKind::DomainController, true, false),
        ],
        edges: vec![
            link("ws1", "user"),
            link("ws2", "user"),
            link("user", "group"),
            link("group", "server"),
            link("server", "dc"),
        ],
    }
}


fn ladder(entries: &[&str]) -> Graph {
    let mut nodes: Vec<Node> = entries.iter().map(|id| node(id, NodeKind::Workstation, false, true)).collect();
    let mut edges: Vec<Edge> = Vec::new();
    nodes.push(node("sink", NodeKind::DomainController, true, false));
    (0..LADDER_LAYERS).for_each(|layer| {
        ["a", "b"]
            .iter()
            .for_each(|side| nodes.push(node(&format!("l{layer:02}{side}"), NodeKind::Server, false, false)));
        let next: Vec<String> = if layer + 1 == LADDER_LAYERS {
            vec!["sink".to_string()]
        } else {
            vec![format!("l{:02}a", layer + 1), format!("l{:02}b", layer + 1)]
        };
        ["a", "b"].iter().for_each(|side| {
            next.iter().for_each(|target| edges.push(link(&format!("l{layer:02}{side}"), target)));
        });
    });
    entries.iter().for_each(|entry| {
        edges.push(link(entry, "l00a"));
        edges.push(link(entry, "l00b"));
    });
    Graph { nodes, edges }
}


#[test]
fn ad_graph_gives_the_expected_paths() -> TestResult {
    let found = paths_to_critical(&ad_graph(), limits(LADDER_DEPTH, LADDER_CAP))?;
    assert!(!found.truncated);
    assert_eq!(
        found.paths,
        vec![
            route(&["ws1", "user", "group", "server", "dc"]),
            route(&["ws2", "user", "group", "server", "dc"]),
        ]
    );
    Ok(())
}


#[test]
fn a_cycle_terminates_with_simple_paths_only() -> TestResult {
    let graph = Graph {
        nodes: vec![
            node("entry", NodeKind::Workstation, false, true),
            node("a", NodeKind::Server, false, false),
            node("b", NodeKind::Server, false, false),
            node("vault", NodeKind::SecretsVault, true, false),
        ],
        edges: vec![link("entry", "a"), link("a", "b"), link("b", "a"), link("b", "vault"), link("a", "a")],
    };
    let found = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_CAP))?;
    assert_eq!(found.paths, vec![route(&["entry", "a", "b", "vault"])]);
    assert!(!found.truncated);
    Ok(())
}


#[test]
fn parallel_edges_do_not_repeat_a_path() -> TestResult {
    let mut graph = ad_graph();
    graph.edges.push(link("server", "dc"));
    graph.edges.push(link("ws1", "user"));
    let found = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_CAP))?;
    assert_eq!(found.paths.len(), TWO_PATHS);
    Ok(())
}


#[test]
fn a_dense_ladder_is_cut_visibly_and_deterministically() -> TestResult {
    let graph = ladder(&["e1", "e2"]);
    let first = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_CAP))?;
    let second = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_CAP))?;
    assert!(first.truncated);
    assert_eq!(first.paths.len(), LADDER_CAP);
    assert_eq!(first, second);
    assert!(first.paths.iter().all(|path| path.nodes.first().map(String::as_str) == Some("e1")));
    Ok(())
}


#[test]
fn every_entry_is_searched_while_under_the_cap() -> TestResult {
    let graph = ladder(&["e1", "e2"]);
    let found = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_PATHS * TWO_PATHS))?;
    assert!(!found.truncated);
    assert_eq!(found.paths.len(), LADDER_PATHS * TWO_PATHS);
    Ok(())
}


#[test]
fn exactly_the_cap_is_not_a_cut() -> TestResult {
    let graph = ladder(&["e1"]);
    let found = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_PATHS))?;
    assert!(!found.truncated);
    assert_eq!(found.paths.len(), LADDER_PATHS);
    let cut = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_PATHS - 1))?;
    assert!(cut.truncated);
    assert_eq!(cut.paths.len(), LADDER_PATHS - 1);
    Ok(())
}


#[test]
fn a_later_entry_after_a_full_first_one_is_cut() -> TestResult {
    let found = paths_to_critical(&ad_graph(), limits(LADDER_DEPTH, 1))?;
    assert!(found.truncated);
    assert_eq!(found.paths, vec![route(&["ws1", "user", "group", "server", "dc"])]);
    Ok(())
}


#[test]
fn the_depth_limit_counts_edges() -> TestResult {
    let graph = ad_graph();
    let short = paths_to_critical(&graph, limits(CHAIN_LENGTH - 1, LADDER_CAP))?;
    assert!(short.paths.is_empty());
    let enough = paths_to_critical(&graph, limits(CHAIN_LENGTH, LADDER_CAP))?;
    assert_eq!(enough.paths.len(), TWO_PATHS);
    Ok(())
}


#[test]
fn an_entry_that_is_the_only_critical_node_has_no_path() -> TestResult {
    let graph = Graph {
        nodes: vec![node("dc", NodeKind::DomainController, true, true)],
        edges: Vec::new(),
    };
    let found = paths_to_critical(&graph, limits(LADDER_DEPTH, LADDER_CAP))?;
    assert!(found.paths.is_empty());
    assert!(!found.truncated);
    Ok(())
}


#[test]
fn limits_outside_the_bounds_are_refused() -> TestResult {
    let graph = ad_graph();
    assert!(matches!(
        paths_to_critical(&graph, limits(0, 1)),
        Err(PathsError::Limits(LimitsError::Depth { value: 0, .. }))
    ));
    assert!(matches!(
        paths_to_critical(&graph, limits(MAX_DEPTH + 1, 1)),
        Err(PathsError::Limits(LimitsError::Depth { .. }))
    ));
    assert!(matches!(
        paths_to_critical(&graph, limits(1, 0)),
        Err(PathsError::Limits(LimitsError::Paths { value: 0, .. }))
    ));
    assert!(matches!(
        paths_to_critical(&graph, limits(1, MAX_PATHS + 1)),
        Err(PathsError::Limits(LimitsError::Paths { .. }))
    ));
    Ok(())
}


#[test]
fn a_malformed_graph_is_refused_before_the_search() -> TestResult {
    let graph = Graph {
        nodes: vec![node("a", NodeKind::Server, false, true)],
        edges: vec![link("a", "missing")],
    };
    assert!(matches!(
        paths_to_critical(&graph, limits(1, 1)),
        Err(PathsError::Graph(GraphError::UnknownNode { index: 0 }))
    ));
    assert!(validate_graph(&graph).is_err());
    Ok(())
}
