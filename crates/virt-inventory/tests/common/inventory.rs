use crate::fixtures::data;
use serde_json::Value;
use std::error::Error;
use virt_inventory::inventory::{build_inventory, Inventory};
use virt_inventory::limits::Limits;
use virt_inventory::proxmox::parse_resources;


pub fn inventory_of(items: Vec<Value>) -> Result<Inventory, Box<dyn Error>> {
    Ok(build_inventory(
        "acme",
        "pve-1",
        parse_resources(data(items).as_slice(), &Limits::default())?,
    )?)
}
