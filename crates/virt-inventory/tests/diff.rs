#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/inventory.rs"]
mod inventory;
#[path = "common/types.rs"]
mod types;


use core_pg::scope::tenant_of;
use fixtures::{data, guest, node, set, storage, value};
use inventory::inventory_of;
use serde_json::Value;
use types::TestResult;
use virt_inventory::diff::diff;
use virt_inventory::error::InventoryError;
use virt_inventory::inventory::{build_inventory, inventory_cluster, inventory_items, inventory_skipped, inventory_tenant};
use virt_inventory::limits::Limits;
use virt_inventory::model::{ItemKey, Parsed, ResourceKind, Skipped};
use virt_inventory::proxmox::parse_resources;


fn refused(vmid: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut element = guest("qemu", vmid, "x");
    set(&mut element, "/maxcpu", "65537")?;
    Ok(element)
}


fn key(vmid: &str) -> ItemKey {
    ItemKey {
        kind: ResourceKind::Qemu,
        key: vmid.to_owned(),
    }
}


#[test]
fn created_changed_and_retired_are_keyed_by_kind_and_identity() -> TestResult {
    let previous = inventory_of(vec![
        guest("qemu", "100", "web"),
        guest("qemu", "101", "db"),
        node("pve"),
        storage("pve", "local"),
    ])?;
    let mut renamed = guest("qemu", "100", "web2");
    set(&mut renamed, "/status", r#""stopped""#)?;
    let current = inventory_of(vec![renamed, guest("lxc", "102", "ct"), node("pve"), storage("pve", "local")])?;
    let changes = diff(&previous, &current)?;
    assert_eq!(changes.created.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(), ["102"]);
    assert_eq!(changes.retired.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(), ["101"]);
    assert_eq!(changes.retired.first().ok_or("none")?.name.as_deref(), Some("db"));
    assert_eq!(changes.changed.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(), ["100"]);
    assert!(changes.unreadable.is_empty() && changes.retired_unreadable.is_empty());
    Ok(())
}


#[test]
fn a_vmid_reused_under_another_type_is_one_retire_and_one_create() -> TestResult {
    let changes = diff(
        &inventory_of(vec![guest("qemu", "100", "a")])?,
        &inventory_of(vec![guest("lxc", "100", "a")])?,
    )?;
    assert_eq!((changes.created.len(), changes.retired.len(), changes.changed.len()), (1, 1, 0));
    Ok(())
}


#[test]
fn an_unreadable_element_is_never_retired() -> TestResult {
    let previous = inventory_of(vec![guest("qemu", "100", "web"), guest("qemu", "101", "db")])?;
    let current = inventory_of(vec![refused("100")?, guest("qemu", "101", "db")])?;
    let changes = diff(&previous, &current)?;
    assert!(changes.retired.is_empty() && changes.created.is_empty() && changes.changed.is_empty());
    assert_eq!(changes.unreadable, vec![key("100")]);
    assert!(changes.retired_unreadable.is_empty());
    Ok(())
}


#[test]
fn an_element_deleted_while_unreadable_is_retired_unreadable() -> TestResult {
    let before = inventory_of(vec![refused("100")?, refused("101")?, refused("102")?, guest("qemu", "103", "x")])?;
    let after = inventory_of(vec![refused("101")?, guest("qemu", "102", "ok"), guest("qemu", "103", "x")])?;
    let changes = diff(&before, &after)?;
    assert_eq!(changes.retired_unreadable, vec![key("100")]);
    assert_eq!(changes.unreadable, vec![key("101")]);
    assert_eq!(changes.created.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(), ["102"]);
    Ok(())
}


#[test]
fn the_scope_of_the_two_inventories_must_match() -> TestResult {
    let parsed = || parse_resources(data(Vec::new()).as_slice(), &Limits::default());
    let base = build_inventory("acme", "pve-1", parsed()?)?;
    let other_tenant = build_inventory("globex", "pve-1", parsed()?)?;
    let other_cluster = build_inventory("acme", "pve-2", parsed()?)?;
    assert!(matches!(diff(&base, &other_tenant), Err(InventoryError::ScopeMismatch)));
    assert!(matches!(diff(&base, &other_cluster), Err(InventoryError::ScopeMismatch)));
    assert!(diff(&base, &base)?.created.is_empty());
    assert!(InventoryError::ScopeMismatch.to_string().contains("same tenant"));
    Ok(())
}


#[test]
fn the_tenant_and_cluster_follow_the_core_pg_grammar() -> TestResult {
    let empty = || Parsed {
        items: Vec::new(),
        skipped: Skipped::default(),
    };
    let tenant = build_inventory("-x", "pve-1", empty()).err().ok_or("accepted")?;
    assert!(matches!(tenant, InventoryError::Tenant(_)));
    assert!(tenant.to_string().contains("tenant"));
    let cluster = build_inventory("acme", "-x", empty()).err().ok_or("accepted")?;
    assert!(matches!(cluster, InventoryError::Cluster(_)));
    assert!(cluster.to_string().contains("cluster"));
    Ok(())
}


#[test]
fn the_inventory_is_read_through_its_accessors() -> TestResult {
    let current = inventory_of(vec![guest("qemu", "100", "web"), value(r#"{"type":"pool"}"#)])?;
    assert_eq!(tenant_of(inventory_tenant(&current)), "acme");
    assert_eq!(inventory_cluster(&current), "pve-1");
    assert_eq!(inventory_items(&current).len(), 1);
    assert_eq!(inventory_skipped(&current).other_type, 1);
    Ok(())
}


#[test]
fn an_element_unreadable_on_both_sides_is_only_unreadable() -> TestResult {
    let before = inventory_of(vec![refused("100")?])?;
    let after = inventory_of(vec![refused("100")?])?;
    let changes = diff(&before, &after)?;
    assert_eq!(changes.unreadable, vec![key("100")]);
    assert!(changes.retired_unreadable.is_empty() && changes.retired.is_empty());
    Ok(())
}


#[test]
fn a_key_both_kept_and_refused_in_the_previous_list_is_not_retired_unreadable() -> TestResult {
    let overlap = Parsed {
        items: parse_resources(data(vec![guest("qemu", "100", "web")]).as_slice(), &Limits::default())?.items,
        skipped: Skipped {
            refused_keys: vec![key("100")],
            ..Skipped::default()
        },
    };
    let before = build_inventory("acme", "pve-1", overlap)?;
    let after = inventory_of(vec![guest("qemu", "100", "web")])?;
    let changes = diff(&before, &after)?;
    assert!(changes.retired_unreadable.is_empty() && changes.retired.is_empty());
    let gone = diff(&before, &inventory_of(vec![])?)?;
    assert_eq!(gone.retired.len(), 1);
    assert!(gone.retired_unreadable.is_empty());
    Ok(())
}
