#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/types.rs"]
mod types;


use fixtures::{list, node, pod, set};
use k8s_inventory::diff::diff;
use k8s_inventory::inventory::{build_inventory, Inventory};
use k8s_inventory::limits::Limits;
use k8s_inventory::parse::{parse_nodes, parse_pods};
use serde_json::{json, Map, Value};
use types::TestResult;


const LABELS_OVER_CAP: usize = 1_100;


const OWNERS_OVER_CAP: usize = 65;


const CONTAINERS_OVER_CAP: usize = 513;


const ADDRESSES_OVER_CAP: usize = 129;


const NUMERIC_UID: u32 = 7;


const THREE: usize = 3;


const TWO: usize = 2;


const FOUR: usize = 4;


fn labelled(name: &str, uid: &str, count: usize) -> Result<Value, Box<dyn std::error::Error>> {
    let mut item = pod(name, uid);
    let labels = (0..count).map(|i| (format!("k{i}"), json!("v"))).collect::<Map<String, Value>>();
    set(&mut item, "/metadata/labels", Value::Object(labels))?;
    Ok(item)
}


fn inventory(pods: Vec<Value>, nodes: Vec<Value>) -> Result<Inventory, Box<dyn std::error::Error>> {
    let limits = Limits::default();
    Ok(build_inventory(
        "acme",
        "prod-1",
        parse_pods(list("PodList", pods).as_slice(), &limits)?,
        parse_nodes(list("NodeList", nodes).as_slice(), &limits)?,
    )?)
}


#[test]
fn a_pod_over_every_collection_cap_is_unreadable_never_retired() -> TestResult {
    let previous = inventory(vec![pod("big", "u-big"), pod("gone", "u-gone")], vec![node("n", "n-1")])?;
    let mut crowded = pod("big", "u-big");
    set(
        &mut crowded,
        "/metadata/ownerReferences",
        json!(vec![json!({"kind": "A", "name": "b"}); OWNERS_OVER_CAP]),
    )?;
    let mut many_containers = pod("big2", "u-c");
    set(
        &mut many_containers,
        "/spec/containers",
        json!(vec![json!({"image": "a"}); CONTAINERS_OVER_CAP]),
    )?;
    let mut crowded_node = node("n", "n-1");
    set(
        &mut crowded_node,
        "/status/addresses",
        json!(vec![json!({"type": "Hostname", "address": "h"}); ADDRESSES_OVER_CAP]),
    )?;
    let current = inventory(
        vec![labelled("big", "u-big", LABELS_OVER_CAP)?, many_containers, crowded],
        vec![crowded_node],
    )?;
    let changes = diff(&previous, &current)?;
    let retired = changes.retired.iter().map(|item| item.uid.as_str()).collect::<Vec<_>>();
    assert_eq!(retired, vec!["u-gone"]);
    assert_eq!(changes.unreadable, vec!["u-big", "u-c", "u-big", "n-1"]);
    assert!(changes.created.is_empty());
    assert!(changes.changed.is_empty());
    Ok(())
}


#[test]
fn a_refused_element_without_a_usable_uid_is_counted_not_listed() -> TestResult {
    let mut no_uid = labelled("a", "x", LABELS_OVER_CAP)?;
    set(&mut no_uid, "/metadata/uid", Value::Null)?;
    let mut hostile = labelled("b", "-x", LABELS_OVER_CAP)?;
    set(&mut hostile, "/metadata/uid", json!("-x"))?;
    let mut hidden = labelled("c", "x", LABELS_OVER_CAP)?;
    set(&mut hidden, "/metadata/uid", json!("a\u{202e}b"))?;
    let mut numeric = labelled("d", "x", LABELS_OVER_CAP)?;
    set(&mut numeric, "/metadata/uid", json!(NUMERIC_UID))?;
    let parsed = parse_pods(
        list("PodList", vec![no_uid, hostile, hidden, numeric, json!(1)]).as_slice(),
        &Limits::default(),
    )?;
    assert_eq!((parsed.skipped.bad_field, parsed.skipped.unparsable), (THREE, TWO));
    assert!(parsed.skipped.refused_uids.is_empty());
    Ok(())
}


#[test]
fn the_refused_uids_stay_within_the_item_limit() -> TestResult {
    let limits = Limits {
        max_items: THREE,
        ..Limits::default()
    };
    let refused = (0..THREE)
        .map(|i| labelled("p", &format!("u{i}"), LABELS_OVER_CAP))
        .collect::<Result<Vec<_>, _>>()?;
    let parsed = parse_pods(list("PodList", refused).as_slice(), &limits)?;
    assert_eq!(parsed.skipped.refused_uids.len(), limits.max_items);
    let over = (0..FOUR)
        .map(|i| labelled("p", &format!("u{i}"), LABELS_OVER_CAP))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(parse_pods(list("PodList", over).as_slice(), &limits).is_err());
    Ok(())
}


#[test]
fn the_controller_owner_is_kept_else_the_first() -> TestResult {
    let mut owned = pod("web", "u1");
    set(
        &mut owned,
        "/metadata/ownerReferences",
        json!([{"kind": "Helper", "name": "h"}, {"kind": "Deployment", "name": "d", "controller": true}, {"kind": "Forged", "name": "f", "controller": true}]),
    )?;
    let mut plain = pod("web2", "u2");
    set(
        &mut plain,
        "/metadata/ownerReferences",
        json!([{"kind": "A", "name": "a", "controller": false}, {"kind": "B", "name": "b"}]),
    )?;
    let mut none = pod("web3", "u3");
    set(&mut none, "/metadata/ownerReferences", json!([]))?;
    let parsed = parse_pods(list("PodList", vec![owned, plain, none]).as_slice(), &Limits::default())?;
    let owners = parsed.items.iter().map(|item| item.owner_kind.as_deref()).collect::<Vec<_>>();
    assert_eq!(owners, vec![Some("Deployment"), Some("A"), None]);
    Ok(())
}


#[test]
fn extra_labels_count_the_entries_before_merging_like_containers() -> TestResult {
    let limits = Limits {
        max_labels: 1,
        max_containers: 1,
        ..Limits::default()
    };
    let body = r#"{"kind":"PodList","items":[{"metadata":{"name":"w","namespace":"d","uid":"u","labels":{"a":"1","a":"2"}},"spec":{"containers":[{"image":"i"},{"image":"j"}]}}]}"#;
    let parsed = parse_pods(body.as_bytes(), &limits)?;
    let item = parsed.items.first().ok_or("no item")?;
    assert_eq!((item.labels.len(), item.extra_labels, item.extra_containers), (1, 1, 1));
    Ok(())
}
