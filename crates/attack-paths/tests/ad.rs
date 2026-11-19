use ad_posture::model::{BoundHit, Entry, Snapshot, Unreadable};
use attack_paths::ad::{graph_from_snapshot, kind_of, label_of, node_id, LABEL_CUT_MARKER, MAX_LABEL_BYTES, MAX_MEMBER_OF_PER_NODE, NODE_ID_PREFIX};
use attack_paths::bounds::validate_graph;
use attack_paths::model::{Limits, NodeKind, Tags, MAX_DEPTH, MAX_EDGES, MAX_NODES, MAX_NODE_ID_BYTES, MAX_PATHS};
use attack_paths::paths::paths_to_critical;
use attack_paths::tags::apply_tags;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const TWO: usize = 2;


const THREE: usize = 3;


const OBSERVED: u64 = 2;


const WIDE_GROUPS: usize = MAX_MEMBER_OF_PER_NODE + 2;


const OVER_CAP: usize = MAX_MEMBER_OF_PER_NODE + 1;


const SERVER_TRUST: u32 = 0x2000;


const WIDE_NODES: usize = 1_200;


const FIRST_LINKS: usize = 500;


const FULL_LINKS: usize = 1_000;


const FULL_ENTRIES: usize = 100;


const BIG_DN_BYTES: usize = 65_536;


fn entry(dn: &str, classes: &[&str], member_of: Vec<String>) -> Entry {
    Entry {
        dn: dn.to_string(),
        classes: classes.iter().map(|class| class.to_string()).collect(),
        account: None,
        uac: 0,
        spns: Vec::new(),
        member_of,
        pwd_last_set: None,
        last_logon: None,
        sid: None,
        gaps: Vec::new(),
    }
}


fn snapshot_of(entries: Vec<Entry>) -> Snapshot {
    Snapshot {
        entries,
        unreadable: Vec::new(),
        bounds: Vec::new(),
    }
}


fn group_named(index: usize, links: usize, total: usize) -> Entry {
    let targets = (1..=links).map(|offset| format!("CN=g{},DC=x", (index + offset) % total)).collect();
    entry(&format!("CN=g{index},DC=x"), &["group"], targets)
}


#[test]
fn kinds_follow_class_and_trust_bit() -> TestResult {
    let mut controller = entry("CN=dc,DC=x", &["top", "computer"], Vec::new());
    controller.uac = SERVER_TRUST;
    let mut user_with_bit = entry("CN=u,DC=x", &["user"], Vec::new());
    user_with_bit.uac = SERVER_TRUST;
    assert_eq!(kind_of(&controller), NodeKind::DomainController);
    assert_eq!(kind_of(&user_with_bit), NodeKind::User);
    assert_eq!(kind_of(&entry("CN=w,DC=x", &["Computer"], Vec::new())), NodeKind::Workstation);
    assert_eq!(kind_of(&entry("CN=g,DC=x", &["group", "computer"], Vec::new())), NodeKind::Group);
    Ok(())
}


#[test]
fn id_is_bounded_and_case_insensitive() -> TestResult {
    let huge = "A".repeat(BIG_DN_BYTES);
    assert!(node_id(&huge).len() <= MAX_NODE_ID_BYTES);
    assert!(node_id(&huge).starts_with(NODE_ID_PREFIX));
    assert_eq!(node_id("CN=Alice,DC=X"), node_id("cn=alice,dc=x"));
    assert_ne!(node_id("CN=a,DC=x"), node_id("CN=b,DC=x"));
    Ok(())
}


#[test]
fn label_is_clean_and_cut_with_a_marker() -> TestResult {
    let mut hostile = entry("CN=x,DC=x", &["user"], Vec::new());
    hostile.account = Some("al\u{1b}[31m\u{202e}ice".to_string());
    let label = label_of(&hostile);
    assert!(!label.chars().any(|found| found.is_control() || found == '\u{202e}'));
    assert!(label.contains('?'));
    let long = entry(&"\u{e9}".repeat(BIG_DN_BYTES), &["user"], Vec::new());
    let cut = label_of(&long);
    assert!(cut.ends_with(LABEL_CUT_MARKER));
    assert!(cut.len() <= MAX_LABEL_BYTES + LABEL_CUT_MARKER.len());
    assert_eq!(label_of(&entry("CN=short,DC=x", &["user"], Vec::new())), "CN=short,DC=x");
    Ok(())
}


#[test]
fn member_of_matches_case_insensitively_and_unknown_is_counted() -> TestResult {
    let built = graph_from_snapshot(&snapshot_of(vec![
        entry(
            "CN=Alice,DC=x",
            &["user"],
            vec!["cn=ADMINS,dc=X".to_string(), "CN=ghost,DC=x".to_string(), "CN=ADMINS,DC=x".to_string()],
        ),
        entry("CN=Admins,DC=x", &["group"], vec!["CN=Admins,DC=x".to_string()]),
    ]));
    assert_eq!(built.graph.nodes.len(), TWO);
    assert_eq!(built.graph.edges.len(), 1);
    assert_eq!(built.skipped.unknown_target, 1);
    assert_eq!(built.skipped.repeated_edge, TWO);
    assert!(!built.truncated);
    assert_eq!(built.labels.len(), TWO);
    let edge = built.graph.edges.first().ok_or("no edge")?;
    assert_eq!(edge.from, node_id("CN=Alice,DC=x"));
    assert_eq!(edge.to, node_id("CN=Admins,DC=x"));
    validate_graph(&built.graph)?;
    Ok(())
}


#[test]
fn duplicate_case_variant_keeps_the_first() -> TestResult {
    let built = graph_from_snapshot(&snapshot_of(vec![
        entry("CN=Dup,DC=x", &["user"], Vec::new()),
        entry("cn=dup,dc=x", &["group"], Vec::new()),
    ]));
    assert_eq!(built.graph.nodes.len(), 1);
    assert_eq!(built.skipped.duplicate_dn, 1);
    assert_eq!(built.graph.nodes.first().map(|node| node.kind), Some(NodeKind::User));
    Ok(())
}


#[test]
fn unreadable_and_bound_hits_are_carried() -> TestResult {
    let mut snapshot = snapshot_of(vec![entry("CN=a,DC=x", &["user"], Vec::new())]);
    snapshot.unreadable.push(Unreadable {
        index: 1,
        field: "memberOf",
        reason: "bad",
        dn_digest: "00".to_string(),
        group_risk: false,
        account: None,
        sid: None,
    });
    snapshot.bounds.push(BoundHit {
        bound: "entries",
        observed: OBSERVED,
        limit: 1,
    });
    let built = graph_from_snapshot(&snapshot);
    assert_eq!(built.skipped.unreadable, 1);
    assert!(built.truncated);
    Ok(())
}


#[test]
fn over_node_bound_truncates_loudly() -> TestResult {
    let entries = (0..=MAX_NODES)
        .map(|index| entry(&format!("CN=u{index},DC=x"), &["user"], Vec::new()))
        .collect();
    let built = graph_from_snapshot(&snapshot_of(entries));
    assert_eq!(built.graph.nodes.len(), MAX_NODES);
    assert_eq!(built.skipped.over_nodes, 1);
    assert!(built.truncated);
    validate_graph(&built.graph)?;
    Ok(())
}


#[test]
fn per_entry_edge_cap_keeps_the_node() -> TestResult {
    let wide = group_named(0, OVER_CAP, WIDE_GROUPS);
    let others = (1..(WIDE_GROUPS)).map(|index| group_named(index, 0, WIDE_GROUPS));
    let built = graph_from_snapshot(&snapshot_of(std::iter::once(wide).chain(others).collect()));
    assert_eq!(built.skipped.over_member_cap, 1);
    assert!(built.graph.edges.is_empty());
    assert_eq!(built.graph.nodes.len(), WIDE_GROUPS);
    Ok(())
}


#[test]
fn over_edge_bound_truncates_loudly() -> TestResult {
    let entries = (0..WIDE_NODES)
        .map(|index| {
            let links = if index == 0 {
                FIRST_LINKS
            } else if index <= FULL_ENTRIES {
                FULL_LINKS
            } else {
                0
            };
            group_named(index, links, WIDE_NODES)
        })
        .collect::<Vec<_>>();
    let mut with_late = entries;
    with_late.push(group_named(WIDE_NODES, FULL_LINKS, WIDE_NODES));
    let built = graph_from_snapshot(&snapshot_of(with_late));
    assert_eq!(built.graph.edges.len(), MAX_EDGES);
    assert!(built.truncated);
    assert!(built.skipped.over_edges >= FIRST_LINKS + FULL_LINKS);
    validate_graph(&built.graph)?;
    Ok(())
}


#[test]
fn hostile_group_only_adds_its_own_edges() -> TestResult {
    let admins = "CN=Domain Admins,DC=x";
    let mut entries = vec![
        entry(admins, &["group"], Vec::new()),
        entry("CN=alice,DC=x", &["user"], vec![admins.to_string()]),
    ];
    entries.push(entry("CN=evil,DC=x", &["group"], vec![admins.to_string()]));
    let built = graph_from_snapshot(&snapshot_of(entries));
    assert_eq!(built.graph.nodes.len(), THREE);
    assert!(built.labels.contains_key(&node_id(admins)));
    assert_eq!(built.graph.edges.len(), TWO);
    Ok(())
}


#[test]
fn cycle_builds_and_search_ends() -> TestResult {
    let mut built = graph_from_snapshot(&snapshot_of(vec![
        entry("CN=a,DC=x", &["group"], vec!["CN=b,DC=x".to_string()]),
        entry("CN=b,DC=x", &["group"], vec!["CN=a,DC=x".to_string(), "CN=top,DC=x".to_string()]),
        entry("CN=top,DC=x", &["group"], Vec::new()),
    ]));
    let start = node_id("CN=a,DC=x");
    let top = node_id("CN=top,DC=x");
    built.graph.nodes.iter_mut().for_each(|node| {
        node.entry_point = node.id == start;
        node.critical = node.id == top;
    });
    let found = paths_to_critical(
        &built.graph,
        Limits {
            max_depth: MAX_DEPTH,
            max_paths: MAX_PATHS,
        },
    )?;
    assert_eq!(found.paths.len(), 1);
    let tags = Tags { critical: vec![start] };
    apply_tags(&mut built.graph, &tags)?;
    Ok(())
}
