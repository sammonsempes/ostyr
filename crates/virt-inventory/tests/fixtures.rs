#[path = "common/types.rs"]
mod types;


use types::TestResult;
use virt_inventory::diff::diff;
use virt_inventory::error::ReadOnlyError;
use virt_inventory::inventory::{build_inventory, inventory_items, inventory_skipped, Inventory};
use virt_inventory::limits::Limits;
use virt_inventory::model::ResourceKind;
use virt_inventory::proxmox::{parse_permissions, parse_resources};
use virt_inventory::readonly::check_read_only;


const BEFORE: &[u8] = include_bytes!("fixtures/resources-before.json");


const AFTER: &[u8] = include_bytes!("fixtures/resources-after.json");


const ADMIN: &[u8] = include_bytes!("fixtures/resources-admin.json");


const AUDITOR_PERMISSIONS: &[u8] = include_bytes!("fixtures/permissions-auditor.json");


const ADMIN_PERMISSIONS: &[u8] = include_bytes!("fixtures/permissions-admin.json");


const FLAG_ZERO_PERMISSIONS: &[u8] = include_bytes!("fixtures/permissions-flag0.json");


const BEFORE_COUNT: usize = 5;


fn inventory_of(bytes: &[u8]) -> Result<Inventory, Box<dyn std::error::Error>> {
    Ok(build_inventory("lab", "pve-lab", parse_resources(bytes, &Limits::default())?)?)
}


#[test]
fn the_live_auditor_resources_parse_with_only_the_sdn_entry_skipped() -> TestResult {
    let inventory = inventory_of(BEFORE)?;
    assert_eq!(inventory_items(&inventory).len(), BEFORE_COUNT);
    assert_eq!(inventory_skipped(&inventory).other_type, 1);
    assert_eq!(inventory_skipped(&inventory).bad_field + inventory_skipped(&inventory).unparsable, 0);
    let kinds = inventory_items(&inventory).iter().map(|item| item.kind).collect::<Vec<_>>();
    assert_eq!(
        kinds,
        [
            ResourceKind::Qemu,
            ResourceKind::Qemu,
            ResourceKind::Lxc,
            ResourceKind::Node,
            ResourceKind::Storage
        ]
    );
    Ok(())
}


#[test]
fn the_live_admin_token_sees_guests_and_the_node_only() -> TestResult {
    let inventory = inventory_of(ADMIN)?;
    assert!(inventory_items(&inventory).iter().all(|item| item.kind != ResourceKind::Storage));
    Ok(())
}


#[test]
fn a_destroyed_guest_is_retired_in_the_live_diff() -> TestResult {
    let changes = diff(&inventory_of(BEFORE)?, &inventory_of(AFTER)?)?;
    assert_eq!(changes.retired.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(), ["9002"]);
    assert!(changes.created.is_empty() && changes.unreadable.is_empty());
    Ok(())
}


#[test]
fn the_live_permissions_decide_the_read_only_check() -> TestResult {
    let limits = Limits::default();
    assert_eq!(check_read_only(&parse_permissions(AUDITOR_PERMISSIONS, &limits)?), Ok(()));
    let admin = check_read_only(&parse_permissions(ADMIN_PERMISSIONS, &limits)?);
    assert!(matches!(
        admin,
        Err(ReadOnlyError::HasWriteRights { privileges, .. }) if privileges.iter().any(|name| name == "VM.PowerMgmt")
    ));
    let flag_zero = check_read_only(&parse_permissions(FLAG_ZERO_PERMISSIONS, &limits)?);
    assert!(matches!(flag_zero, Err(ReadOnlyError::HasWriteRights { .. })));
    Ok(())
}
