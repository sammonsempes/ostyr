//! Usage: `k8s_inventory <pods.json> <nodes.json> [previous-pods.json] [previous-nodes.json]`, or `k8s_inventory pages <page.json>...`.
use core_pg::scope::tenant_of;
use k8s_inventory::diff::diff;
use k8s_inventory::error::ParseError;
use k8s_inventory::inventory::{
    build_inventory, inventory_cluster, inventory_nodes, inventory_pods, inventory_skipped_nodes, inventory_skipped_pods, inventory_tenant, Inventory,
};
use k8s_inventory::limits::{Limits, PageLimits};
use k8s_inventory::model::{ItemRef, Parsed, PodItem};
use k8s_inventory::pages::{merge_pod_pages, remaining_budget};
use k8s_inventory::parse::{parse_nodes, parse_pods, parse_pods_page};
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};


const PREVIOUS_ARGUMENT: usize = 2;


const PREVIOUS_NODES_ARGUMENT: usize = 3;


const PAGES_MODE: &str = "pages";


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


fn pod_line(pod: &PodItem) -> String {
    format!(
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
}


fn run_pages(paths: &[String]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let limits = Limits::default();
    let page_limits = PageLimits::default();
    let mut pages = Vec::new();
    for path in paths {
        let budget = remaining_budget(&pages, &page_limits);
        pages.push(parse_pods_page(File::open(path)?, &limits, budget)?);
    }
    let mut out = stdout();
    match merge_pod_pages(pages, &page_limits) {
        Ok(parsed) => {
            writeln!(out, "pods={} skipped_pods={:?}", parsed.items.len(), parsed.skipped)?;
            parsed.items.iter().try_for_each(|pod| writeln!(out, "{}", pod_line(pod)))?;
        }
        Err(ParseError::Incomplete) => writeln!(out, "incomplete")?,
        Err(other) => Err(other)?,
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) == Some(PAGES_MODE) {
        run_pages(arguments.get(1..).ok_or("missing page files")?)
    } else {
        run_inventory(&arguments)
    }
}


fn run_inventory(arguments: &[String]) -> Result<(), Box<dyn Error + Send + Sync>> {
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
    inventory_pods(&current).iter().try_for_each(|pod| writeln!(out, "{}", pod_line(pod)))?;
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
            parse_nodes(
                File::open(arguments.get(PREVIOUS_NODES_ARGUMENT).or(arguments.get(1)).ok_or("missing nodes.json")?)?,
                &limits,
            )?,
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
        changes
            .unreadable
            .iter()
            .try_for_each(|item| writeln!(out, "unreadable {:?} uid={}", item.kind, item.uid))?;
        changes
            .retired_unreadable
            .iter()
            .try_for_each(|item| writeln!(out, "retired_unreadable {:?} uid={}", item.kind, item.uid))?;
    }
    Ok(())
}
