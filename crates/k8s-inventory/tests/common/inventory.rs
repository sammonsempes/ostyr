use crate::fixtures::list;
use k8s_inventory::inventory::{build_inventory, Inventory};
use k8s_inventory::limits::Limits;
use k8s_inventory::parse::{parse_nodes, parse_pods};
use serde_json::Value;
use std::error::Error;


pub fn inventory_of(pods: Vec<Value>, nodes: Vec<Value>) -> Result<Inventory, Box<dyn Error>> {
    let limits = Limits::default();
    Ok(build_inventory(
        "acme",
        "prod-1",
        parse_pods(list("PodList", pods).as_slice(), &limits)?,
        parse_nodes(list("NodeList", nodes).as_slice(), &limits)?,
    )?)
}
