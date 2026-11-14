//! Usage: `proxmox_fetch <settings.yaml> [<previous-resources.json>]`. Fetches the inventory over HTTPS (read-only token check first) and prints it or the refusal; with a previous `/cluster/resources` answer it prints the diff.
use core_pg::scope::tenant_of;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use virt_inventory::diff::diff;
use virt_inventory::fetch::fetch_inventory;
use virt_inventory::inventory::{build_inventory, inventory_cluster, inventory_degraded_nodes, inventory_items, inventory_skipped, inventory_tenant};
use virt_inventory::model::ItemRef;
use virt_inventory::proxmox::parse_resources;
use virt_inventory::settings::load_settings;


const PREVIOUS_ARGUMENT: usize = 1;


fn line_of(label: &str, item: &ItemRef) -> String {
    format!("{label} {:?} key={} name={:?} node={}", item.kind, item.key, item.name, item.node)
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let settings = load_settings(std::path::Path::new(arguments.first().ok_or("missing settings.yaml")?))?;
    let mut out = stdout();
    let current = match fetch_inventory(&settings) {
        Ok(inventory) => inventory,
        Err(refusal) => {
            writeln!(out, "refused: {refusal}")?;
            Err(refusal)?
        }
    };
    let degraded = inventory_degraded_nodes(&current);
    writeln!(
        out,
        "tenant={} cluster={} items={} degraded={} degraded_nodes={:?} skipped={:?}",
        tenant_of(inventory_tenant(&current)),
        inventory_cluster(&current),
        inventory_items(&current).len(),
        !degraded.is_empty(),
        degraded,
        inventory_skipped(&current)
    )?;
    inventory_items(&current).iter().try_for_each(|item| {
        writeln!(
            out,
            "item {:?} key={} name={:?} node={} status={:?}",
            item.kind, item.key, item.name, item.node, item.status
        )
    })?;
    if let Some(previous_path) = arguments.get(PREVIOUS_ARGUMENT) {
        let parsed = parse_resources(File::open(previous_path)?, &settings.limits)?;
        let changes = diff(&build_inventory(&settings.tenant, &settings.cluster, parsed)?, &current)?;
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
