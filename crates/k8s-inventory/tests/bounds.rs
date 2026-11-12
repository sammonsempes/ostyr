#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/types.rs"]
mod types;


use fixtures::{list, node, pod, set};
use k8s_inventory::limits::{Limits, COLLECTION_SLACK};
use k8s_inventory::parse::{parse_nodes, parse_pods, OWNERS_SCANNED};
use serde_json::{json, Map, Value};
use types::TestResult;


const OVER_SLACK: usize = 9;


const OVER_OWNER_SLACK: usize = 65;


fn tight() -> Limits {
    Limits {
        max_containers: 1,
        max_labels: 1,
        max_addresses: 1,
        ..Limits::default()
    }
}


fn pod_with(pointer: &str, value: Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut item = pod("web", "u1");
    set(&mut item, pointer, value)?;
    Ok(list("PodList", vec![item]))
}


fn labels_of(count: usize) -> Value {
    Value::Object((0..count).map(|i| (format!("k{i}"), json!("v"))).collect::<Map<String, Value>>())
}


#[test]
fn a_collection_above_the_slack_refuses_the_element() -> TestResult {
    assert_eq!(COLLECTION_SLACK + 1, OVER_SLACK);
    assert_eq!(OWNERS_SCANNED * COLLECTION_SLACK + 1, OVER_OWNER_SLACK);
    let many_containers = pod_with("/spec/containers", json!(vec![json!({"image": "a"}); OVER_SLACK]))?;
    assert_eq!(parse_pods(many_containers.as_slice(), &tight())?.skipped.bad_field, 1);
    let many_owners = pod_with(
        "/metadata/ownerReferences",
        json!(vec![json!({"kind": "A", "name": "b"}); OVER_OWNER_SLACK]),
    )?;
    assert_eq!(parse_pods(many_owners.as_slice(), &Limits::default())?.skipped.bad_field, 1);
    let many_labels = pod_with("/metadata/labels", labels_of(OVER_SLACK))?;
    assert_eq!(parse_pods(many_labels.as_slice(), &tight())?.skipped.bad_field, 1);
    let mut crowded = node("n", "n1");
    set(
        &mut crowded,
        "/status/addresses",
        json!(vec![json!({"type": "Hostname", "address": "h"}); OVER_SLACK]),
    )?;
    let nodes = parse_nodes(list("NodeList", vec![crowded]).as_slice(), &tight())?;
    assert_eq!(nodes.skipped.bad_field, 1);
    Ok(())
}


#[test]
fn up_to_the_slack_the_extra_entries_are_counted_not_refused() -> TestResult {
    let body = pod_with("/metadata/labels", labels_of(COLLECTION_SLACK))?;
    let parsed = parse_pods(body.as_slice(), &tight())?;
    let item = parsed.items.first().ok_or("no item")?;
    assert_eq!((item.labels.len(), item.extra_labels), (1, COLLECTION_SLACK - 1));
    Ok(())
}


#[test]
fn null_or_wrong_typed_collections_are_empty_or_unparsable() -> TestResult {
    let nulls = pod_with("/metadata/labels", Value::Null)?;
    assert_eq!(parse_pods(nulls.as_slice(), &Limits::default())?.items.len(), 1);
    let not_a_map = pod_with("/metadata/labels", json!([1]))?;
    assert_eq!(parse_pods(not_a_map.as_slice(), &Limits::default())?.skipped.unparsable, 1);
    let not_a_list = pod_with("/spec/containers", json!({"a": 1}))?;
    assert_eq!(parse_pods(not_a_list.as_slice(), &Limits::default())?.skipped.unparsable, 1);
    Ok(())
}
