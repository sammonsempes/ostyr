use std::collections::BTreeMap;
use std::net::IpAddr;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodItem {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub node_name: Option<String>,
    pub phase: Option<String>,
    pub images: Vec<String>,
    pub extra_containers: usize,
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub extra_labels: usize,
    pub created_unix: Option<i64>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeItem {
    pub name: String,
    pub uid: String,
    pub kubelet_version: Option<String>,
    pub os_image: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub extra_addresses: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Unparsable,
    BadField,
    Duplicate,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Skipped {
    pub unparsable: usize,
    pub bad_field: usize,
    pub duplicate: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<Item> {
    pub items: Vec<Item>,
    pub skipped: Skipped,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemKind {
    Pod,
    Node,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub kind: ItemKind,
    pub uid: String,
    pub namespace: Option<String>,
    pub name: String,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryDiff {
    pub created: Vec<ItemRef>,
    pub retired: Vec<ItemRef>,
    pub changed: Vec<ItemRef>,
}
