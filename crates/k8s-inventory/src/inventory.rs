use crate::error::InventoryError;
use crate::model::{NodeItem, Parsed, PodItem, Skipped};
use core_pg::scope::{tenant_scope, TenantScope};


/// One cluster's pods and nodes for one tenant; the scope is fixed at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub tenant: TenantScope,
    pub cluster: String,
    pub pods: Vec<PodItem>,
    pub nodes: Vec<NodeItem>,
    pub skipped_pods: Skipped,
    pub skipped_nodes: Skipped,
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
