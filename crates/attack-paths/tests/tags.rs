use attack_paths::error::TagsError;
use attack_paths::model::{Graph, Node, NodeKind, Tags, MAX_TAGS};
use attack_paths::tags::{apply_tags, check_tags, kind_is_critical};
use types::TestResult;


#[path = "support/types.rs"]
mod types;


fn node(id: &str, kind: NodeKind, critical: bool) -> Node {
    Node {
        id: id.to_string(),
        kind,
        critical,
        entry_point: false,
    }
}


#[test]
fn only_the_listed_kinds_are_critical() -> TestResult {
    let critical = [
        NodeKind::DomainController,
        NodeKind::AdCs,
        NodeKind::BackupServer,
        NodeKind::Hypervisor,
        NodeKind::SecretsVault,
    ];
    let plain = [
        NodeKind::Workstation,
        NodeKind::User,
        NodeKind::Group,
        NodeKind::Server,
        NodeKind::CloudRole,
        NodeKind::Internet,
    ];
    assert!(critical.iter().all(|kind| kind_is_critical(*kind)));
    assert!(plain.iter().all(|kind| !kind_is_critical(*kind)));
    Ok(())
}


#[test]
fn kinds_and_manual_tags_mark_nodes_and_keep_existing_marks() -> TestResult {
    let mut graph = Graph {
        nodes: vec![
            node("dc", NodeKind::DomainController, false),
            node("file", NodeKind::Server, false),
            node("kept", NodeKind::Server, true),
            node("plain", NodeKind::Server, false),
        ],
        edges: Vec::new(),
    };
    let tags = Tags {
        critical: vec!["file".to_string()],
    };
    apply_tags(&mut graph, &tags)?;
    let flags: Vec<bool> = graph.nodes.iter().map(|each| each.critical).collect();
    assert_eq!(flags, vec![true, true, true, false]);
    Ok(())
}


#[test]
fn a_tag_naming_no_node_is_refused() -> TestResult {
    let mut graph = Graph {
        nodes: vec![node("a", NodeKind::Server, false)],
        edges: Vec::new(),
    };
    let tags = Tags {
        critical: vec!["a".to_string(), "ghost".to_string()],
    };
    assert!(matches!(apply_tags(&mut graph, &tags), Err(TagsError::UnknownNode { index: 1 })));
    Ok(())
}


#[test]
fn too_many_tags_are_refused() -> TestResult {
    let tags = Tags {
        critical: vec!["a".to_string(); MAX_TAGS + 1],
    };
    assert!(matches!(check_tags(tags), Err(TagsError::TooMany { max: MAX_TAGS, .. })));
    Ok(())
}
