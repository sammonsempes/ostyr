use crate::error::InventoryError;
use crate::model::{NodeItem, Parsed, PodItem, Skipped};
use core_pg::scope::{tenant_scope, TenantScope};


/// One cluster's pods and nodes for one tenant; only `build_inventory` builds one, the fields are read through the `inventory_*` functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub(crate) tenant: TenantScope,
    pub(crate) cluster: String,
    pub(crate) pods: Vec<PodItem>,
    pub(crate) nodes: Vec<NodeItem>,
    pub(crate) skipped_pods: Skipped,
    pub(crate) skipped_nodes: Skipped,
}


pub fn inventory_tenant(inventory: &Inventory) -> &TenantScope {
    &inventory.tenant
}


pub fn inventory_cluster(inventory: &Inventory) -> &str {
    &inventory.cluster
}


pub fn inventory_pods(inventory: &Inventory) -> &[PodItem] {
    &inventory.pods
}


pub fn inventory_nodes(inventory: &Inventory) -> &[NodeItem] {
    &inventory.nodes
}


pub fn inventory_skipped_pods(inventory: &Inventory) -> &Skipped {
    &inventory.skipped_pods
}


pub fn inventory_skipped_nodes(inventory: &Inventory) -> &Skipped {
    &inventory.skipped_nodes
}


/// The tenant and the cluster id follow the core-pg tenant grammar (at most 64 characters, no leading `-`).
pub fn build_inventory(tenant: &str, cluster: &str, pods: Parsed<PodItem>, nodes: Parsed<NodeItem>) -> Result<Inventory, InventoryError> {
    let scope = tenant_scope(tenant).map_err(InventoryError::Tenant)?;
    tenant_scope(cluster).map_err(InventoryError::Cluster)?;
    Ok(Inventory {
        tenant: scope,
        cluster: cluster.to_owned(),
        pods: pods.items,
        nodes: nodes.items,
        skipped_pods: pods.skipped,
        skipped_nodes: nodes.skipped,
    })
}
