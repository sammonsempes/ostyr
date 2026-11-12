#[path = "common/types.rs"]
mod types;


use k8s_inventory::diff::diff;
use k8s_inventory::inventory::{build_inventory, Inventory};
use k8s_inventory::limits::Limits;
use k8s_inventory::parse::{parse_nodes, parse_pods};
use types::TestResult;


const NODES: &[u8] = include_bytes!("fixtures/nodes.json");


const PODS_BEFORE: &[u8] = include_bytes!("fixtures/pods-before.json");


const PODS_AFTER: &[u8] = include_bytes!("fixtures/pods-after.json");


const PODS_AFTER_COUNT: usize = 11;


const SLEEPERS_AND_DELETED_POD: usize = 3;


const SLEEPERS: usize = 2;


fn inventory_of(pods: &[u8]) -> Result<Inventory, Box<dyn std::error::Error>> {
    let limits = Limits::default();
    Ok(build_inventory(
        "lab",
        "k3s-lab",
        parse_pods(pods, &limits)?,
        parse_nodes(NODES, &limits)?,
    )?)
}


#[test]
fn live_k3s_captures_parse_without_skips() -> TestResult {
    let after = inventory_of(PODS_AFTER)?;
    assert_eq!(after.pods.len(), PODS_AFTER_COUNT);
    assert_eq!(after.nodes.len(), 1);
    assert_eq!(
        (after.skipped_pods.bad_field, after.skipped_pods.unparsable, after.skipped_pods.duplicate),
        (0, 0, 0)
    );
    let node = after.nodes.first().ok_or("no node")?;
    assert_eq!(node.name, "k3s");
    assert_eq!(node.addresses.len(), 1);
    Ok(())
}


#[test]
fn live_k3s_scale_down_and_pod_deletion_leave_no_ghost() -> TestResult {
    let changes = diff(&inventory_of(PODS_BEFORE)?, &inventory_of(PODS_AFTER)?)?;
    assert_eq!(changes.retired.len(), SLEEPERS_AND_DELETED_POD);
    assert_eq!(changes.created.len(), 1);
    let created = changes.created.first().ok_or("no created pod")?;
    assert!(created.name.starts_with("pause-app-"));
    let retired_names = changes.retired.iter().map(|item| item.name.as_str()).collect::<Vec<_>>();
    assert_eq!(retired_names.iter().filter(|name| name.starts_with("sleeper-")).count(), SLEEPERS);
    assert_eq!(retired_names.iter().filter(|name| name.starts_with("pause-app-")).count(), 1);
    Ok(())
}
