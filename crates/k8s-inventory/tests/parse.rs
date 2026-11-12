#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/reader.rs"]
mod reader;
#[path = "common/types.rs"]
mod types;


use fixtures::{list, node, pod, set};
use k8s_inventory::error::ParseError;
use k8s_inventory::limits::{Limits, DEFAULT_MAX_BYTES, DEFAULT_MAX_CONTAINERS, DEFAULT_MAX_ITEMS};
use k8s_inventory::model::{NodeItem, PodItem, Skipped};
use k8s_inventory::parse::{parse_nodes, parse_pods};
use reader::FailingReader;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use types::TestResult;


const SMALL_BYTES: u64 = 64;


const TEXT_CAP: usize = 8;


const TWO: usize = 2;


const FOUR: usize = 4;


const EIGHT: usize = 8;


const PADDING: usize = 28;


const OVERSIZED_TEXT: usize = 600;


const FIRST_OF_2024_UNIX: i64 = 1_714_557_600;


fn limits_of(change: fn(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    change(&mut limits);
    limits
}


fn pods_of(items: Vec<Value>) -> Result<k8s_inventory::model::Parsed<PodItem>, ParseError> {
    parse_pods(list("PodList", items).as_slice(), &Limits::default())
}


fn nodes_of(items: Vec<Value>) -> Result<k8s_inventory::model::Parsed<NodeItem>, ParseError> {
    parse_nodes(list("NodeList", items).as_slice(), &Limits::default())
}


#[test]
fn a_full_pod_is_parsed() -> TestResult {
    let parsed = pods_of(vec![pod("web-1", "uid-1")])?;
    let expected = PodItem {
        namespace: "default".to_owned(),
        name: "web-1".to_owned(),
        uid: "uid-1".to_owned(),
        node_name: Some("node-a".to_owned()),
        phase: Some("Running".to_owned()),
        images: vec!["nginx:1.27".to_owned(), "busybox:1".to_owned()],
        extra_containers: 0,
        owner_kind: Some("ReplicaSet".to_owned()),
        owner_name: Some("web-1".to_owned()),
        labels: BTreeMap::from([
            ("app".to_owned(), "web".to_owned()),
            ("app.kubernetes.io/name".to_owned(), "nginx".to_owned()),
        ]),
        extra_labels: 0,
        created_unix: Some(FIRST_OF_2024_UNIX),
    };
    assert_eq!(parsed.items, vec![expected]);
    assert_eq!(parsed.skipped, Skipped::default());
    Ok(())
}


#[test]
fn a_minimal_pod_needs_only_namespace_name_and_uid() -> TestResult {
    let parsed = pods_of(vec![
        json!({"metadata": {"name": "p", "namespace": "n", "uid": "u"}, "unknown": {"deep": [1, 1]}}),
    ])?;
    let item = parsed.items.first().ok_or("no item")?;
    assert_eq!((item.node_name.clone(), item.phase.clone(), item.owner_kind.clone()), (None, None, None));
    assert_eq!((item.images.len(), item.labels.len(), item.created_unix), (0, 0, None));
    Ok(())
}


#[test]
fn containers_and_labels_are_capped_and_the_rest_counted() -> TestResult {
    let limits = limits_of(|bounds| {
        bounds.max_containers = 1;
        bounds.max_labels = 1;
    });
    let parsed = parse_pods(list("PodList", vec![pod("web", "u")]).as_slice(), &limits)?;
    let item = parsed.items.first().ok_or("no item")?;
    assert_eq!(item.images, vec!["nginx:1.27".to_owned()]);
    assert_eq!(item.extra_containers, 1);
    assert_eq!(item.labels, BTreeMap::from([("app".to_owned(), "web".to_owned())]));
    assert_eq!(item.extra_labels, 1);
    Ok(())
}


#[test]
fn a_malformed_element_is_skipped_with_its_reason() -> TestResult {
    let mut missing_name = pod("x", "u2");
    set(&mut missing_name, "/metadata/name", Value::Null)?;
    let mut bad_image = pod("x", "u3");
    set(&mut bad_image, "/spec/containers", json!([{"image": "a\u{202e}b"}]))?;
    let mut dash_label = pod("x", "u4");
    set(&mut dash_label, "/metadata/labels", json!({"-x": "y"}))?;
    let mut bidi_label = pod("x", "u5");
    set(&mut bidi_label, "/metadata/labels", json!({"app": "v\u{202e}"}))?;
    let mut bad_time = pod("x", "u6");
    set(&mut bad_time, "/metadata/creationTimestamp", json!("yesterday"))?;
    let mut owner_without_kind = pod("x", "u7");
    set(&mut owner_without_kind, "/metadata/ownerReferences", json!([{"name": "n"}]))?;
    let mut newline_phase = pod("x", "u8");
    set(&mut newline_phase, "/status/phase", json!("Run\nning"))?;
    let mut empty_image = pod("x", "u9");
    set(&mut empty_image, "/spec/containers", json!([{}]))?;
    let not_an_object = json!("pod");
    let wrong_type = json!({"metadata": "x"});
    let parsed = pods_of(vec![
        pod("ok", "u1"),
        missing_name,
        bad_image,
        dash_label,
        bidi_label,
        bad_time,
        owner_without_kind,
        newline_phase,
        empty_image,
        not_an_object,
        wrong_type,
    ])?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(
        parsed.skipped,
        Skipped {
            unparsable: TWO,
            bad_field: EIGHT,
            duplicate: 0
        }
    );
    Ok(())
}


#[test]
fn a_text_above_the_cap_skips_the_element() -> TestResult {
    let mut long_name = pod("x", "u1");
    set(&mut long_name, "/metadata/name", json!("a".repeat(OVERSIZED_TEXT)))?;
    let parsed = pods_of(vec![long_name])?;
    assert_eq!((parsed.items.len(), parsed.skipped.bad_field), (0, 1));
    let tiny = limits_of(|bounds| bounds.max_text_bytes = TEXT_CAP);
    let parsed_tiny = parse_pods(list("PodList", vec![pod("web-1", "uid-12345")]).as_slice(), &tiny)?;
    assert_eq!((parsed_tiny.items.len(), parsed_tiny.skipped.bad_field), (0, 1));
    Ok(())
}


#[test]
fn a_recreated_pod_keeps_its_name_but_a_repeated_uid_is_a_duplicate() -> TestResult {
    let parsed = pods_of(vec![pod("web", "u1"), pod("web", "u2"), pod("other", "u1")])?;
    assert_eq!(parsed.items.len(), TWO);
    assert_eq!(parsed.skipped.duplicate, 1);
    Ok(())
}


#[test]
fn the_list_must_be_a_pod_list_with_an_items_array() -> TestResult {
    let secret = parse_pods(list("Secret", vec![]).as_slice(), &Limits::default());
    assert!(matches!(secret, Err(ParseError::WrongKind { expected: "PodList" })));
    let nodes_as_pods = parse_pods(list("NodeList", vec![]).as_slice(), &Limits::default());
    assert!(matches!(nodes_as_pods, Err(ParseError::WrongKind { .. })));
    let pods_as_nodes = parse_nodes(list("PodList", vec![]).as_slice(), &Limits::default());
    assert!(matches!(pods_as_nodes, Err(ParseError::WrongKind { expected: "NodeList" })));
    let object_items = json!({"kind": "PodList", "items": {"a": 1}}).to_string();
    assert!(matches!(
        parse_pods(object_items.as_bytes(), &Limits::default()),
        Err(ParseError::Malformed { .. })
    ));
    let null_items = json!({"kind": "PodList", "items": null}).to_string();
    assert!(matches!(
        parse_pods(null_items.as_bytes(), &Limits::default()),
        Err(ParseError::Malformed { .. })
    ));
    assert!(matches!(parse_pods(&b"{"[..], &Limits::default()), Err(ParseError::Malformed { .. })));
    assert!(matches!(parse_pods(&b"{}"[..], &Limits::default()), Err(ParseError::Malformed { .. })));
    Ok(())
}


#[test]
fn the_item_count_is_checked_before_any_element_is_parsed() -> TestResult {
    let limits = limits_of(|bounds| bounds.max_items = 1);
    let body = json!({"kind": "PodList", "items": ["not a pod", {"metadata": []}]}).to_string();
    let error = parse_pods(body.as_bytes(), &limits);
    assert!(matches!(error, Err(ParseError::TooManyItems { count: TWO, max: 1 })));
    let exact = limits_of(|bounds| bounds.max_items = TWO);
    assert!(parse_pods(body.as_bytes(), &exact).is_ok());
    Ok(())
}


#[test]
fn bytes_are_capped_before_parsing() -> TestResult {
    let limits = limits_of(|bounds| bounds.max_bytes = SMALL_BYTES);
    let body = list("PodList", vec![pod("web", "u")]);
    assert!(matches!(
        parse_pods(body.as_slice(), &limits),
        Err(ParseError::TooLarge { max: SMALL_BYTES })
    ));
    let at_cap = format!("{{\"kind\":\"PodList\",\"items\":[],\"x\":\"{}\"}}", "a".repeat(PADDING));
    assert_eq!(at_cap.len() as u64, SMALL_BYTES);
    assert!(parse_pods(at_cap.as_bytes(), &limits).is_ok());
    let over_by_one = format!("{at_cap} ");
    assert!(matches!(parse_pods(over_by_one.as_bytes(), &limits), Err(ParseError::TooLarge { .. })));
    Ok(())
}


#[test]
fn a_failing_reader_is_reported_with_its_cause() -> TestResult {
    let error = parse_pods(FailingReader, &Limits::default()).err().ok_or("no error")?;
    assert!(matches!(error, ParseError::Read(_)));
    assert_eq!(error.to_string(), "cannot read the list: injected read failure");
    Ok(())
}


#[test]
fn error_messages_do_not_echo_the_input() -> TestResult {
    let hostile = r#"{"kind":"PodList","items":"SECRET-TOKEN"}"#;
    let message = parse_pods(hostile.as_bytes(), &Limits::default()).err().ok_or("no error")?.to_string();
    assert!(!message.contains("SECRET-TOKEN"), "{message}");
    Ok(())
}


#[test]
fn default_limits_are_the_documented_ones() -> TestResult {
    let limits = Limits::default();
    assert_eq!(
        (limits.max_bytes, limits.max_items, limits.max_containers),
        (DEFAULT_MAX_BYTES, DEFAULT_MAX_ITEMS, DEFAULT_MAX_CONTAINERS)
    );
    Ok(())
}


#[test]
fn a_node_is_parsed_with_its_internal_addresses() -> TestResult {
    let parsed = nodes_of(vec![node("node-a", "n1")])?;
    let expected = NodeItem {
        name: "node-a".to_owned(),
        uid: "n1".to_owned(),
        kubelet_version: Some("v1.30.2+k3s1".to_owned()),
        os_image: Some("Ubuntu 24.04 LTS".to_owned()),
        addresses: vec!["10.0.0.5".parse()?],
        extra_addresses: 0,
    };
    assert_eq!(parsed.items, vec![expected]);
    Ok(())
}


#[test]
fn node_addresses_are_capped_and_bad_ones_skip_the_node() -> TestResult {
    let mut many = node("many", "n2");
    set(
        &mut many,
        "/status/addresses",
        json!([
            {"type": "InternalIP", "address": "10.0.0.1"},
            {"type": "InternalIP", "address": "fd00::1"},
            {"type": "ExternalIP", "address": "not an address"}
        ]),
    )?;
    let limits = limits_of(|bounds| bounds.max_addresses = 1);
    let capped = parse_nodes(list("NodeList", vec![many]).as_slice(), &limits)?;
    let item = capped.items.first().ok_or("no item")?;
    assert_eq!((item.addresses.len(), item.extra_addresses), (1, 1));
    let mut bad_ip = node("bad", "n3");
    set(&mut bad_ip, "/status/addresses", json!([{"type": "InternalIP", "address": "10.0.0.256"}]))?;
    let mut no_ip = node("none", "n4");
    set(&mut no_ip, "/status/addresses", json!([{"type": "InternalIP"}]))?;
    let mut bad_version = node("ver", "n5");
    set(&mut bad_version, "/status/nodeInfo/kubeletVersion", json!("v1\u{202e}"))?;
    let mut no_uid = node("nouid", "n6");
    set(&mut no_uid, "/metadata/uid", Value::Null)?;
    let bare = json!({"metadata": {"name": "bare", "uid": "n7"}});
    let parsed = nodes_of(vec![bad_ip, no_ip, bad_version, no_uid, bare, json!(1)])?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(
        parsed.skipped,
        Skipped {
            unparsable: 1,
            bad_field: FOUR,
            duplicate: 0
        }
    );
    Ok(())
}


#[test]
fn a_node_uid_repeated_is_a_duplicate() -> TestResult {
    let parsed = nodes_of(vec![node("a", "n1"), node("b", "n1")])?;
    assert_eq!((parsed.items.len(), parsed.skipped.duplicate), (1, 1));
    Ok(())
}
