//! Usage: `k8s_inventory <pods.json> <nodes.json> [previous-pods.json]`. Prints the inventory and, with a previous pod list, the diff.
use core_pg::scope::tenant_of;
use k8s_inventory::diff::diff;
use k8s_inventory::inventory::{
    build_inventory, inventory_cluster, inventory_nodes, inventory_pods, inventory_skipped_nodes, inventory_skipped_pods, inventory_tenant, Inventory,
};
use k8s_inventory::limits::Limits;
use k8s_inventory::model::{ItemRef, Parsed, PodItem};
use k8s_inventory::parse::{parse_nodes, parse_pods};
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};


const PREVIOUS_ARGUMENT: usize = 2;


const TENANT: &str = "lab";


const CLUSTER: &str = "k3s-lab";


fn pods_of(path: &str, limits: &Limits) -> Result<Parsed<PodItem>, Box<dyn Error + Send + Sync>> {
    Ok(parse_pods(File::open(path)?, limits)?)
}


fn inventory_of(pods_path: &str, nodes_path: &str, limits: &Limits) -> Result<Inventory, Box<dyn Error + Send + Sync>> {
    let nodes = parse_nodes(File::open(nodes_path)?, limits)?;
    Ok(build_inventory(TENANT, CLUSTER, pods_of(pods_path, limits)?, nodes)?)
}


fn line_of(label: &str, item: &ItemRef) -> String {
    format!(
        "{label} {:?} uid={} namespace={:?} name={}",
        item.kind, item.uid, item.namespace, item.name
    )
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let limits = Limits::default();
    let current = inventory_of(
        arguments.first().ok_or("missing pods.json")?,
        arguments.get(1).ok_or("missing nodes.json")?,
        &limits,
    )?;
    let mut out = stdout();
    writeln!(
        out,
        "tenant={} cluster={} pods={} nodes={} skipped_pods={:?} skipped_nodes={:?}",
        tenant_of(inventory_tenant(&current)),
        inventory_cluster(&current),
        inventory_pods(&current).len(),
        inventory_nodes(&current).len(),
        inventory_skipped_pods(&current),
        inventory_skipped_nodes(&current)
    )?;
    inventory_pods(&current).iter().try_for_each(|pod| {
        writeln!(
            out,
            "pod {}/{} uid={} node={:?} phase={:?} owner={:?}/{:?} images={:?} extra_containers={} labels={} extra_labels={}",
            pod.namespace,
            pod.name,
            pod.uid,
            pod.node_name,
            pod.phase,
            pod.owner_kind,
            pod.owner_name,
            pod.images,
            pod.extra_containers,
            pod.labels.len(),
            pod.extra_labels
        )
    })?;
    inventory_nodes(&current).iter().try_for_each(|node| {
        writeln!(
            out,
            "node {} uid={} kubelet={:?} os={:?} addresses={:?}",
            node.name, node.uid, node.kubelet_version, node.os_image, node.addresses
        )
    })?;
    if let Some(previous_path) = arguments.get(PREVIOUS_ARGUMENT) {
        let previous = build_inventory(
            TENANT,
            CLUSTER,
            pods_of(previous_path, &limits)?,
            parse_nodes(File::open(arguments.get(1).ok_or("missing nodes.json")?)?, &limits)?,
        )?;
        let changes = diff(&previous, &current)?;
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
        changes.unreadable.iter().try_for_each(|uid| writeln!(out, "unreadable uid={uid}"))?;
    }
    Ok(())
}
