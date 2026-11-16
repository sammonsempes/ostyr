use attack_paths::bounds::validate_graph;
use attack_paths::error::GraphError;
use attack_paths::model::{Edge, Graph, Node, NodeKind, Relation, MAX_EDGES, MAX_NODES, MAX_NODE_ID_BYTES};
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const DUPLICATE_INDEX: usize = 2;


fn node(id: &str) -> Node {
    Node {
        id: id.to_string(),
        kind: NodeKind::Server,
        critical: false,
        entry_point: false,
    }
}


fn link(from: &str, to: &str) -> Edge {
    Edge {
        from: from.to_string(),
        to: to.to_string(),
        relation: Relation::MemberOf,
    }
}


#[test]
fn a_valid_graph_passes_and_the_id_bounds_are_inclusive() -> TestResult {
    let longest = "x".repeat(MAX_NODE_ID_BYTES);
    let graph = Graph {
        nodes: vec![node("a"), node(&longest)],
        edges: vec![link("a", &longest)],
    };
    assert!(validate_graph(&graph).is_ok());
    Ok(())
}


#[test]
fn too_many_nodes_or_edges_are_refused_by_count() -> TestResult {
    let nodes = Graph {
        nodes: (0..=MAX_NODES).map(|index| node(&index.to_string())).collect(),
        edges: Vec::new(),
    };
    assert!(matches!(validate_graph(&nodes), Err(GraphError::TooManyNodes { max: MAX_NODES, .. })));
    let edges = Graph {
        nodes: vec![node("a")],
        edges: (0..=MAX_EDGES).map(|_| link("a", "a")).collect(),
    };
    assert!(matches!(validate_graph(&edges), Err(GraphError::TooManyEdges { max: MAX_EDGES, .. })));
    Ok(())
}


#[test]
fn bad_ids_duplicates_and_unknown_ends_name_the_index() -> TestResult {
    let empty = Graph {
        nodes: vec![node("a"), node("")],
        edges: Vec::new(),
    };
    assert!(matches!(validate_graph(&empty), Err(GraphError::BadNodeId { index: 1, .. })));
    let long = Graph {
        nodes: vec![node(&"x".repeat(MAX_NODE_ID_BYTES + 1))],
        edges: Vec::new(),
    };
    assert!(matches!(validate_graph(&long), Err(GraphError::BadNodeId { index: 0, .. })));
    let twice = Graph {
        nodes: vec![node("a"), node("b"), node("a")],
        edges: Vec::new(),
    };
    assert!(matches!(
        validate_graph(&twice),
        Err(GraphError::DuplicateNode { index: DUPLICATE_INDEX })
    ));
    let from = Graph {
        nodes: vec![node("a")],
        edges: vec![link("a", "a"), link("ghost", "a")],
    };
    assert!(matches!(validate_graph(&from), Err(GraphError::UnknownNode { index: 1 })));
    let to = Graph {
        nodes: vec![node("a")],
        edges: vec![link("a", "ghost")],
    };
    assert!(matches!(validate_graph(&to), Err(GraphError::UnknownNode { index: 0 })));
    Ok(())
}
