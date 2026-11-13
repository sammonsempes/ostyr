//! Usage: `proxmox_inventory <resources.json> <permissions.json> [previous-resources.json]`. Prints the inventory, the read-only verdict and, with a previous list, the diff.
use core_pg::scope::tenant_of;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use virt_inventory::diff::diff;
use virt_inventory::inventory::{build_inventory, inventory_cluster, inventory_items, inventory_skipped, inventory_tenant, Inventory};
use virt_inventory::limits::Limits;
use virt_inventory::model::ItemRef;
use virt_inventory::proxmox::{parse_permissions, parse_resources};
use virt_inventory::readonly::check_read_only;


const PERMISSIONS_ARGUMENT: usize = 1;


const PREVIOUS_ARGUMENT: usize = 2;


const TENANT: &str = "lab";


const CLUSTER: &str = "pve-lab";


fn inventory_of(path: &str, limits: &Limits) -> Result<Inventory, Box<dyn Error + Send + Sync>> {
    Ok(build_inventory(TENANT, CLUSTER, parse_resources(File::open(path)?, limits)?)?)
}


fn line_of(label: &str, item: &ItemRef) -> String {
    format!("{label} {:?} key={} name={:?} node={}", item.kind, item.key, item.name, item.node)
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let limits = Limits::default();
    let current = inventory_of(arguments.first().ok_or("missing resources.json")?, &limits)?;
    let permissions = parse_permissions(
        File::open(arguments.get(PERMISSIONS_ARGUMENT).ok_or("missing permissions.json")?)?,
        &limits,
    )?;
    let mut out = stdout();
    writeln!(
        out,
        "tenant={} cluster={} items={} skipped={:?}",
        tenant_of(inventory_tenant(&current)),
        inventory_cluster(&current),
        inventory_items(&current).len(),
        inventory_skipped(&current)
    )?;
    inventory_items(&current).iter().try_for_each(|item| {
        writeln!(
            out,
            "item {:?} key={} name={:?} node={} status={:?} cpu={:?} mem={:?} disk={:?} template={}",
            item.kind, item.key, item.name, item.node, item.status, item.max_cpu, item.max_mem, item.max_disk, item.template
        )
    })?;
    match check_read_only(&permissions) {
        Ok(()) => writeln!(out, "read-only: ok")?,
        Err(refusal) => writeln!(out, "read-only: refused: {refusal}")?,
    }
    if let Some(previous_path) = arguments.get(PREVIOUS_ARGUMENT) {
        let changes = diff(&inventory_of(previous_path, &limits)?, &current)?;
        changes
            .created
            .iter()
            .try_for_each(|item| writeln!(out, "{}", line_of("created", item)))?;
        changes
            .retired
            .iter()
            .try_for_each(|item| writeln!(out, "{}", line_of("retired", item)))?;
        changes
            .changed
            .iter()
            .try_for_each(|item| writeln!(out, "{}", line_of("changed", item)))?;
        changes
            .unreadable
            .iter()
            .try_for_each(|item| writeln!(out, "unreadable {:?} key={}", item.kind, item.key))?;
        changes
            .retired_unreadable
            .iter()
            .try_for_each(|item| writeln!(out, "retired_unreadable {:?} key={}", item.kind, item.key))?;
    }
    Ok(())
}
