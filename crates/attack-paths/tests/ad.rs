use ad_posture::model::{BoundHit, Entry, Gap, Snapshot, Unreadable};
use ad_posture::snapshot::digest_prefix;
use attack_paths::ad::{
    apply_ad_tags, graph_from_snapshot, incomplete_of, kind_of, label_of, node_id, unreadable_digest, FIELD_MEMBER_OF, LABEL_CUT_MARKER,
    MAX_LABEL_BYTES, MAX_MEMBER_OF_PER_NODE, NODE_ID_PREFIX, REASON_GAP, REASON_OVER_EDGES, REASON_OVER_MEMBER_CAP, REASON_OVER_NODES_TARGET,
    REASON_UNREADABLE_TARGET,
};
use attack_paths::bounds::validate_graph;
use attack_paths::model::{Limits, NodeKind, Tags, MAX_DEPTH, MAX_EDGES, MAX_NODES, MAX_NODE_ID_BYTES, MAX_PATHS};
use attack_paths::paths::paths_to_critical;
use attack_paths::tags::{apply_tags, apply_tags_lenient, SkippedTag};
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
    assert_eq!(label_of(&entry("CN=short,DC=x", &["user"], Vec::new())), "CN?short?DC?x");
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
    let late = node_id(&format!("CN=g{WIDE_NODES},DC=x"));
    let mid = node_id(&format!("CN=g{FULL_ENTRIES},DC=x"));
    let named = |id: &String| {
        built
            .incomplete
            .iter()
            .find(|node| node.reason == REASON_OVER_EDGES && node.id == *id)
            .map(|node| node.dropped)
    };
    assert_eq!(named(&late), Some(FULL_LINKS));
    assert_eq!(named(&mid), Some(FIRST_LINKS));
    assert!(built.incomplete.iter().all(|node| node.field == FIELD_MEMBER_OF && !node.over_limit));
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


fn gap(field: &'static str, dropped: usize, over_limit: bool) -> Gap {
    Gap { field, dropped, over_limit }
}


fn victim_snapshot(gaps: Vec<Gap>) -> Snapshot {
    let mut victim = entry("CN=hd,DC=x", &["user"], Vec::new());
    victim.gaps = gaps;
    snapshot_of(vec![entry("CN=Domain Admins,DC=x", &["group"], Vec::new()), victim])
}


#[test]
fn member_of_backlink_flood_is_loud_and_names_the_victim() -> TestResult {
    let built = graph_from_snapshot(&victim_snapshot(vec![gap(FIELD_MEMBER_OF, WIDE_GROUPS, true)]));
    assert!(built.truncated);
    assert!(built.graph.edges.is_empty());
    let named = built.incomplete.first().ok_or("victim not named")?;
    assert_eq!(named.id, node_id("CN=hd,DC=x"));
    assert_eq!(named.digest, digest_prefix("CN=hd,DC=x"));
    assert_eq!((named.field, named.dropped, named.over_limit), (FIELD_MEMBER_OF, WIDE_GROUPS, true));
    assert_eq!(built.incomplete.len(), 1);
    Ok(())
}


#[test]
fn dropped_values_and_object_class_gaps_are_reported_but_spns_are_not() -> TestResult {
    let dropped = graph_from_snapshot(&victim_snapshot(vec![gap(FIELD_MEMBER_OF, 1, false)]));
    assert!(dropped.truncated);
    assert_eq!(dropped.incomplete.len(), 1);
    let classes = graph_from_snapshot(&victim_snapshot(vec![gap("objectClass", TWO, true)]));
    assert!(classes.truncated);
    assert_eq!(classes.incomplete.first().map(|node| node.field), Some("objectClass"));
    let spns = graph_from_snapshot(&victim_snapshot(vec![gap("servicePrincipalName", TWO, true)]));
    assert!(!spns.truncated);
    assert!(spns.incomplete.is_empty());
    let victim = entry("CN=hd,DC=x", &["user"], Vec::new());
    assert!(incomplete_of("id", &victim).is_empty());
    Ok(())
}


#[test]
fn victim_under_the_cap_keeps_the_path() -> TestResult {
    let admins = "CN=Domain Admins,DC=x";
    let mut targets: Vec<String> = (0..MAX_MEMBER_OF_PER_NODE - 1).map(|index| format!("CN=g{index},DC=x")).collect();
    targets.push(admins.to_string());
    let mut entries = vec![entry(admins, &["group"], Vec::new()), entry("CN=hd,DC=x", &["user"], targets)];
    entries.extend((0..MAX_MEMBER_OF_PER_NODE - 1).map(|index| entry(&format!("CN=g{index},DC=x"), &["group"], Vec::new())));
    let mut built = graph_from_snapshot(&snapshot_of(entries));
    assert!(!built.truncated);
    let start = node_id("CN=hd,DC=x");
    let top = node_id(admins);
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
    Ok(())
}


#[test]
fn over_member_cap_sets_truncated() -> TestResult {
    let wide = group_named(0, OVER_CAP, WIDE_GROUPS);
    let built = graph_from_snapshot(&snapshot_of(vec![wide]));
    assert!(built.truncated);
    assert_eq!(built.skipped.over_member_cap, 1);
    let named = built.incomplete.first().ok_or("wide entry not named")?;
    assert_eq!((named.reason, named.dropped, named.over_limit), (REASON_OVER_MEMBER_CAP, OVER_CAP, true));
    assert_eq!(named.digest, digest_prefix("CN=g0,DC=x"));
    Ok(())
}


#[test]
fn kelvin_sign_does_not_merge_with_ascii_k() -> TestResult {
    let kelvin = "CN=\u{212a}ADM,DC=x";
    let real = "CN=kADM,DC=x";
    assert_ne!(node_id(kelvin), node_id(real));
    let built = graph_from_snapshot(&snapshot_of(vec![
        entry(kelvin, &["computer"], vec!["CN=Domain Admins,DC=x".to_string()]),
        entry(real, &["user"], vec!["CN=Domain Admins,DC=x".to_string()]),
        entry("CN=Domain Admins,DC=x", &["group"], Vec::new()),
    ]));
    assert_eq!(built.graph.nodes.len(), THREE);
    assert_eq!(built.graph.edges.len(), TWO);
    assert_eq!(built.skipped.duplicate_dn, 0);
    assert!(!built.truncated);
    Ok(())
}


#[test]
fn duplicate_dn_is_named_by_both_digests_and_truncates() -> TestResult {
    let built = graph_from_snapshot(&snapshot_of(vec![
        entry("CN=Dup,DC=x", &["user"], Vec::new()),
        entry("cn=dup,dc=x", &["group"], Vec::new()),
    ]));
    assert!(built.truncated);
    let named = built.duplicates.first().ok_or("duplicate not named")?;
    assert_eq!(named.kept_digest, digest_prefix("CN=Dup,DC=x"));
    assert_eq!(named.dropped_digest, digest_prefix("cn=dup,dc=x"));
    Ok(())
}


#[test]
fn labels_use_an_ascii_allowlist() -> TestResult {
    let mut hostile = entry("CN=x,DC=x", &["user"], Vec::new());
    hostile.account = Some("Domain\u{3164}Admins \u{430}._$-=".to_string());
    assert_eq!(label_of(&hostile), "Domain?Admins ?._$-?");
    Ok(())
}


#[test]
fn lenient_tags_return_the_skipped_ones() -> TestResult {
    let mut built = graph_from_snapshot(&snapshot_of(vec![entry("CN=a,DC=x", &["user"], Vec::new())]));
    let gone = node_id("CN=gone,DC=x");
    let tags = Tags {
        critical: vec![node_id("CN=a,DC=x"), gone.clone(), node_id("CN=gone2,DC=x")],
    };
    assert!(apply_tags(&mut built.graph, &tags).is_err());
    let skipped = apply_tags_lenient(&mut built.graph, &tags);
    assert_eq!(skipped.len(), TWO);
    assert_eq!(skipped.first(), Some(&SkippedTag { index: 1, id: gone }));
    assert!(built.graph.nodes.iter().all(|node| node.critical));
    Ok(())
}


#[test]
fn one_bad_member_of_value_removes_no_node() -> TestResult {
    let mut victim = entry("CN=hd,DC=x", &["user"], Vec::new());
    victim.gaps = vec![gap(FIELD_MEMBER_OF, 1, false)];
    let built = graph_from_snapshot(&snapshot_of(vec![victim]));
    assert!(built.truncated);
    assert!(built.removed_ids.is_empty());
    assert_eq!(built.incomplete.first().map(|node| node.reason), Some(REASON_GAP));
    Ok(())
}


#[test]
fn tags_are_lenient_only_for_a_removed_node() -> TestResult {
    let wrong = Tags {
        critical: vec![node_id("CN=gone,DC=x")],
    };
    let mut hostile = entry("CN=evil,DC=x", &["user"], Vec::new());
    hostile.gaps = vec![gap(FIELD_MEMBER_OF, 1, false)];
    let mut unreadable = snapshot_of(vec![hostile]);
    unreadable.unreadable.push(unreadable_with("00".to_string()));
    unreadable.bounds.push(BoundHit {
        bound: "entries",
        observed: OBSERVED,
        limit: 1,
    });
    let mut truncated = graph_from_snapshot(&unreadable);
    assert!(truncated.truncated);
    assert!(apply_ad_tags(&mut truncated, &wrong).is_err());
    let mut fine = graph_from_snapshot(&snapshot_of(vec![entry("CN=a,DC=x", &["user"], Vec::new())]));
    assert!(apply_ad_tags(&mut fine, &Tags::default())?.is_empty());
    let mut dups = graph_from_snapshot(&snapshot_of(vec![
        entry("CN=a,DC=x", &["user"], Vec::new()),
        entry("cn=a,dc=x", &["user"], Vec::new()),
    ]));
    assert!(apply_ad_tags(&mut dups, &wrong).is_err());
    Ok(())
}


#[test]
fn a_tag_naming_an_entry_cut_at_max_nodes_is_skipped() -> TestResult {
    let wide = (0..=MAX_NODES)
        .map(|index| entry(&format!("CN=n{index},DC=x"), &["user"], Vec::new()))
        .collect();
    let mut built = graph_from_snapshot(&snapshot_of(wide));
    let cut = node_id(&format!("CN=n{MAX_NODES},DC=x"));
    assert_eq!(built.removed_ids.len(), 1);
    let skipped = apply_ad_tags(
        &mut built,
        &Tags {
            critical: vec![node_id("CN=n0,DC=x"), cut.clone()],
        },
    )?;
    assert_eq!(skipped, vec![SkippedTag { index: 1, id: cut }]);
    assert!(apply_ad_tags(
        &mut built,
        &Tags {
            critical: vec![node_id("CN=other,DC=x")]
        }
    )
    .is_err());
    Ok(())
}


#[test]
fn unreadable_alone_truncates() -> TestResult {
    let mut snapshot = snapshot_of(vec![entry("CN=a,DC=x", &["user"], Vec::new())]);
    snapshot.unreadable.push(unreadable_with("00".to_string()));
    let built = graph_from_snapshot(&snapshot);
    assert!(built.truncated);
    assert!(built.incomplete.is_empty());
    Ok(())
}


fn unreadable_with(dn_digest: String) -> Unreadable {
    Unreadable {
        index: 1,
        field: "dn",
        reason: "bad",
        dn_digest,
        group_risk: false,
        account: None,
        sid: None,
    }
}


#[test]
fn unreadable_entry_truncates_and_marks_its_members_incomplete() -> TestResult {
    let admins = "CN=Domain Admins,DC=x";
    let mut snapshot = snapshot_of(vec![
        entry("CN=hd,DC=x", &["user"], vec![admins.to_string()]),
        entry("CN=ok,DC=x", &["user"], vec!["CN=other,DC=x".to_string()]),
    ]);
    snapshot.unreadable.push(unreadable_with(unreadable_digest(admins)));
    let built = graph_from_snapshot(&snapshot);
    assert!(built.truncated);
    assert_eq!(built.incomplete.len(), 1);
    let named = built.incomplete.first().ok_or("member not named")?;
    assert_eq!((named.reason, named.field, named.dropped), (REASON_UNREADABLE_TARGET, FIELD_MEMBER_OF, 1));
    assert_eq!(named.digest, digest_prefix("CN=hd,DC=x"));
    assert_eq!(built.skipped.unknown_target, TWO);
    Ok(())
}


#[test]
fn unreadable_digest_is_the_digest_of_the_json_string() -> TestResult {
    assert_eq!(unreadable_digest("CN=a\\, b,DC=x"), digest_prefix("\"CN=a\\\\, b,DC=x\""));
    Ok(())
}


#[test]
fn digests_name_every_node() -> TestResult {
    let built = graph_from_snapshot(&snapshot_of(vec![entry("CN=a,DC=x", &["user"], Vec::new())]));
    assert_eq!(built.digests.get(&node_id("CN=a,DC=x")), Some(&digest_prefix("CN=a,DC=x")));
    Ok(())
}


#[test]
fn an_edge_into_a_node_cut_at_max_nodes_names_its_source() -> TestResult {
    let mut entries: Vec<Entry> = (0..MAX_NODES - 1)
        .map(|index| entry(&format!("CN=u{index},DC=x"), &["user"], Vec::new()))
        .collect();
    entries.push(entry(
        "CN=hd,DC=x",
        &["user"],
        vec!["CN=ops,DC=x".to_string(), "CN=nobody,DC=x".to_string()],
    ));
    entries.push(entry("CN=ops,DC=x", &["group"], vec!["CN=da,DC=x".to_string()]));
    let built = graph_from_snapshot(&snapshot_of(entries));
    let cut = built
        .incomplete
        .iter()
        .filter(|node| node.reason == REASON_OVER_NODES_TARGET)
        .collect::<Vec<_>>();
    assert_eq!(cut.len(), 1);
    assert_eq!(cut.first().map(|node| (node.id.clone(), node.dropped)), Some((node_id("CN=hd,DC=x"), 1)));
    assert!(built.truncated);
    assert_eq!(built.removed_digests.get(&node_id("CN=ops,DC=x")), Some(&digest_prefix("CN=ops,DC=x")));
    Ok(())
}


#[test]
fn a_tag_naming_a_duplicated_dn_is_refused() -> TestResult {
    let mut built = graph_from_snapshot(&snapshot_of(vec![
        entry("CN=DOMAIN ADMINS,DC=x", &["user"], Vec::new()),
        entry("CN=Domain Admins,DC=x", &["group"], Vec::new()),
    ]));
    let tags = Tags {
        critical: vec![node_id("CN=Domain Admins,DC=x")],
    };
    assert!(apply_ad_tags(&mut built, &tags).is_err());
    Ok(())
}
