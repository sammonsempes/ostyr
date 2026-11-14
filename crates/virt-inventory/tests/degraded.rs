#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/inventory.rs"]
mod inventory;
#[path = "common/types.rs"]
mod types;


use fixtures::{guest, node, set, storage};
use inventory::inventory_of;
use serde_json::Value;
use types::TestResult;
use virt_inventory::diff::diff;
use virt_inventory::inventory::inventory_degraded_nodes;
use virt_inventory::model::{ItemKey, ResourceKind};


fn guest_on(kind: &str, vmid: &str, node_name: &str, status: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut element = guest(kind, vmid, "g");
    set(&mut element, "/node", &format!("\"{node_name}\""))?;
    set(&mut element, "/status", &format!("\"{status}\""))?;
    Ok(element)
}


fn key(kind: ResourceKind, vmid: &str) -> ItemKey {
    ItemKey { kind, key: vmid.to_owned() }
}


#[test]
fn every_guest_unknown_on_a_node_is_degraded_and_unreadable_not_changed() -> TestResult {
    let previous = inventory_of(vec![
        node("pve"),
        storage("pve", "local"),
        guest_on("qemu", "100", "pve", "running")?,
        guest_on("lxc", "101", "pve", "stopped")?,
    ])?;
    let mut stalled_node = node("pve");
    set(&mut stalled_node, "/status", "\"unknown\"")?;
    let mut stalled_storage = storage("pve", "local");
    set(&mut stalled_storage, "/status", "\"unknown\"")?;
    let current = inventory_of(vec![
        stalled_node,
        stalled_storage,
        guest_on("qemu", "100", "pve", "unknown")?,
        guest_on("lxc", "101", "pve", "unknown")?,
    ])?;
    assert_eq!(inventory_degraded_nodes(&current), ["pve".to_owned()]);
    let changes = diff(&previous, &current)?;
    assert!(changes.changed.is_empty());
    assert!(changes.retired.is_empty());
    assert_eq!(
        changes.unreadable,
        vec![
            key(ResourceKind::Qemu, "100"),
            key(ResourceKind::Lxc, "101"),
            key(ResourceKind::Node, "pve"),
            key(ResourceKind::Storage, "pve/local")
        ]
    );
    Ok(())
}


#[test]
fn one_unknown_guest_among_known_ones_stays_a_normal_item() -> TestResult {
    let previous = inventory_of(vec![
        guest_on("qemu", "100", "pve", "running")?,
        guest_on("qemu", "101", "pve", "running")?,
    ])?;
    let current = inventory_of(vec![
        guest_on("qemu", "100", "pve", "unknown")?,
        guest_on("qemu", "101", "pve", "running")?,
    ])?;
    assert!(inventory_degraded_nodes(&current).is_empty());
    let changes = diff(&previous, &current)?;
    assert_eq!(changes.changed.len(), 1);
    assert!(changes.unreadable.is_empty());
    Ok(())
}


#[test]
fn only_the_node_whose_guests_are_all_unknown_is_degraded() -> TestResult {
    let previous = inventory_of(vec![
        guest_on("qemu", "100", "pve", "running")?,
        guest_on("qemu", "200", "pve2", "running")?,
        guest_on("qemu", "201", "pve2", "running")?,
    ])?;
    let current = inventory_of(vec![
        guest_on("qemu", "100", "pve", "unknown")?,
        guest_on("qemu", "200", "pve2", "unknown")?,
        guest_on("qemu", "201", "pve2", "running")?,
        node("pve3"),
    ])?;
    assert_eq!(inventory_degraded_nodes(&current), ["pve".to_owned()]);
    let changes = diff(&previous, &current)?;
    assert_eq!(changes.changed.len(), 1);
    assert_eq!(changes.created.len(), 1);
    assert_eq!(changes.unreadable, vec![key(ResourceKind::Qemu, "100")]);
    Ok(())
}


#[test]
fn a_node_without_guests_and_a_node_item_are_never_degraded() -> TestResult {
    let mut stalled = node("pve");
    set(&mut stalled, "/status", "\"unknown\"")?;
    let previous = inventory_of(vec![node("pve"), storage("pve", "local")])?;
    let current = inventory_of(vec![stalled, storage("pve", "local")])?;
    assert!(inventory_degraded_nodes(&current).is_empty());
    assert_eq!(diff(&previous, &current)?.changed.len(), 1);
    Ok(())
}


#[test]
fn a_new_unknown_guest_on_a_degraded_node_is_created_and_unreadable() -> TestResult {
    let previous = inventory_of(vec![])?;
    let current = inventory_of(vec![guest_on("qemu", "100", "pve", "unknown")?])?;
    let changes = diff(&previous, &current)?;
    assert_eq!(changes.created.len(), 1);
    assert_eq!(changes.unreadable, vec![key(ResourceKind::Qemu, "100")]);
    Ok(())
}
