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


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skipped {
    pub unparsable: usize,
    pub bad_field: usize,
    pub duplicate: usize,
    pub uid_lost: usize,
    pub refused_uids: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<Item> {
    pub items: Vec<Item>,
    pub skipped: Skipped,
}


/// One page of a paged list: its items, the `continue` token of the next page (`None` on the last page) and its raw element count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<Item> {
    pub parsed: Parsed<Item>,
    pub next: Option<String>,
    pub raw_count: usize,
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


/// An item known by kind and uid only: it was refused, so its names are never kept.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnreadableRef {
    pub kind: ItemKind,
    pub uid: String,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryDiff {
    pub created: Vec<ItemRef>,
    pub retired: Vec<ItemRef>,
    pub changed: Vec<ItemRef>,
    pub unreadable: Vec<UnreadableRef>,
    pub retired_unreadable: Vec<UnreadableRef>,
}
