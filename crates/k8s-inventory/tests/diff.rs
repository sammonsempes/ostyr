#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/inventory.rs"]
mod inventory;
#[path = "common/types.rs"]
mod types;


use fixtures::{node, pod, set};
use inventory::inventory_of;
use k8s_inventory::diff::diff;
use k8s_inventory::error::InventoryError;
use k8s_inventory::inventory::{build_inventory, inventory_cluster, inventory_skipped_nodes, inventory_skipped_pods, inventory_tenant};
use k8s_inventory::limits::Limits;
use k8s_inventory::model::{ItemKind, Parsed, Skipped};
use serde_json::json;
use types::TestResult;


fn empty<Item>() -> Parsed<Item> {
    Parsed {
        items: Vec::new(),
        skipped: Skipped::default(),
    }
}


#[test]
fn created_retired_and_changed_are_keyed_by_uid() -> TestResult {
    let mut running = pod("keep", "u-keep");
    set(&mut running, "/status/phase", json!("Pending"))?;
    let previous = inventory_of(
        vec![pod("keep", "u-keep"), pod("gone", "u-gone")],
        vec![node("n", "n-1"), node("old", "n-old")],
    )?;
    let current = inventory_of(vec![running, pod("new", "u-new")], vec![node("n", "n-1"), node("fresh", "n-new")])?;
    let changes = diff(&previous, &current)?;
    let uids = |refs: &[k8s_inventory::model::ItemRef]| refs.iter().map(|item| item.uid.clone()).collect::<Vec<_>>();
    assert_eq!(uids(&changes.created), vec!["u-new", "n-new"]);
    assert_eq!(uids(&changes.retired), vec!["u-gone", "n-old"]);
    assert_eq!(uids(&changes.changed), vec!["u-keep"]);
    let created_pod = changes.created.first().ok_or("no created")?;
    assert_eq!(
        (created_pod.kind, created_pod.namespace.as_deref(), created_pod.name.as_str()),
        (ItemKind::Pod, Some("default"), "new")
    );
    let created_node = changes.created.get(1).ok_or("no created node")?;
    assert_eq!((created_node.kind, created_node.namespace.clone()), (ItemKind::Node, None));
    Ok(())
}


#[test]
fn a_recreated_pod_with_the_same_name_is_a_retire_plus_a_create() -> TestResult {
    let previous = inventory_of(vec![pod("web", "uid-old")], vec![])?;
    let current = inventory_of(vec![pod("web", "uid-new")], vec![])?;
    let changes = diff(&previous, &current)?;
    assert_eq!(changes.created.len(), 1);
    assert_eq!(changes.retired.len(), 1);
    assert!(changes.changed.is_empty());
    assert_eq!(changes.retired.first().map(|item| item.uid.as_str()), Some("uid-old"));
    Ok(())
}


#[test]
fn identical_inventories_have_an_empty_diff() -> TestResult {
    let inventory = inventory_of(vec![pod("web", "u")], vec![node("n", "n1")])?;
    let changes = diff(&inventory, &inventory)?;
    assert_eq!((changes.created.len(), changes.retired.len(), changes.changed.len()), (0, 0, 0));
    Ok(())
}


#[test]
fn a_diff_across_tenants_or_clusters_is_refused() -> TestResult {
    let base = inventory_of(vec![pod("web", "u")], vec![])?;
    let other_tenant = build_inventory("globex", "prod-1", empty(), empty())?;
    let other_cluster = build_inventory("acme", "prod-2", empty(), empty())?;
    assert!(matches!(diff(&base, &other_tenant), Err(InventoryError::ScopeMismatch)));
    assert!(matches!(diff(&base, &other_cluster), Err(InventoryError::ScopeMismatch)));
    assert!(matches!(diff(&other_cluster, &base), Err(InventoryError::ScopeMismatch)));
    Ok(())
}


#[test]
fn the_tenant_and_the_cluster_follow_the_core_pg_grammar() -> TestResult {
    assert!(matches!(build_inventory("-x", "c", empty(), empty()), Err(InventoryError::Tenant(_))));
    assert!(matches!(build_inventory("t", "-x", empty(), empty()), Err(InventoryError::Cluster(_))));
    assert!(matches!(build_inventory("t", "", empty(), empty()), Err(InventoryError::Cluster(_))));
    assert!(matches!(build_inventory("t", "a b", empty(), empty()), Err(InventoryError::Cluster(_))));
    Ok(())
}


#[test]
fn skipped_counts_travel_with_the_inventory() -> TestResult {
    let limits = Limits::default();
    let bad = json!({"kind": "PodList", "items": [{"metadata": {"name": "x"}}]}).to_string();
    let pods = k8s_inventory::parse::parse_pods(bad.as_bytes(), &limits)?;
    let inventory = build_inventory("acme", "prod-1", pods, empty())?;
    assert_eq!(inventory_skipped_pods(&inventory).bad_field, 1);
    assert_eq!(inventory_skipped_nodes(&inventory), &Skipped::default());
    Ok(())
}


#[test]
fn the_scope_is_read_back_through_the_accessors() -> TestResult {
    let built = inventory_of(vec![], vec![])?;
    assert_eq!(core_pg::scope::tenant_of(inventory_tenant(&built)), "acme");
    assert_eq!(inventory_cluster(&built), "prod-1");
    Ok(())
}
