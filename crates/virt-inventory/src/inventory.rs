use crate::degraded::degraded_nodes;
use crate::error::InventoryError;
use crate::model::{Parsed, Resource, Skipped};
use core_pg::scope::{tenant_scope, TenantScope};


/// One cluster's resources for one tenant; only `build_inventory` builds one, the fields are read through the `inventory_*` functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub(crate) tenant: TenantScope,
    pub(crate) cluster: String,
    pub(crate) items: Vec<Resource>,
    pub(crate) skipped: Skipped,
    pub(crate) degraded_nodes: Vec<String>,
}


pub fn inventory_tenant(inventory: &Inventory) -> &TenantScope {
    &inventory.tenant
}


pub fn inventory_cluster(inventory: &Inventory) -> &str {
    &inventory.cluster
}


pub fn inventory_items(inventory: &Inventory) -> &[Resource] {
    &inventory.items
}


pub fn inventory_skipped(inventory: &Inventory) -> &Skipped {
    &inventory.skipped
}


/// Nodes whose guests all answered `unknown` (a stalled pvestatd); their guests are `unreadable` in a diff, never `changed`.
pub fn inventory_degraded_nodes(inventory: &Inventory) -> &[String] {
    &inventory.degraded_nodes
}


/// The tenant and the cluster id follow the core-pg tenant grammar (at most 64 characters, no leading `-`).
pub fn build_inventory(tenant: &str, cluster: &str, parsed: Parsed) -> Result<Inventory, InventoryError> {
    let scope = tenant_scope(tenant).map_err(InventoryError::Tenant)?;
    tenant_scope(cluster).map_err(InventoryError::Cluster)?;
    Ok(Inventory {
        tenant: scope,
        cluster: cluster.to_owned(),
        degraded_nodes: degraded_nodes(&parsed.items),
        items: parsed.items,
        skipped: parsed.skipped,
    })
}
