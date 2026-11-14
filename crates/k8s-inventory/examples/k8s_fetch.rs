//! Usage: `k8s_fetch <settings.yaml>`: one read-only run against the Kubernetes API, then the inventory summary or the refusal.
use core_pg::scope::tenant_of;
use k8s_inventory::fetch::fetch_inventory;
use k8s_inventory::inventory::{
    inventory_cluster, inventory_nodes, inventory_pods, inventory_skipped_nodes, inventory_skipped_pods, inventory_tenant,
};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let path = arguments.first().ok_or("missing settings.yaml")?;
    let mut out = stdout();
    match fetch_inventory(Path::new(path)) {
        Ok(inventory) => {
            writeln!(
                out,
                "tenant={} cluster={} pods={} nodes={} skipped_pods={:?} skipped_nodes={:?}",
                tenant_of(inventory_tenant(&inventory)),
                inventory_cluster(&inventory),
                inventory_pods(&inventory).len(),
                inventory_nodes(&inventory).len(),
                inventory_skipped_pods(&inventory),
                inventory_skipped_nodes(&inventory)
            )?;
            inventory_pods(&inventory)
                .iter()
                .try_for_each(|pod| writeln!(out, "pod {}/{} uid={}", pod.namespace, pod.name, pod.uid))?;
            Ok(())
        }
        Err(error) => {
            writeln!(out, "refused: {error}")?;
            Err(Box::new(error))
        }
    }
}
