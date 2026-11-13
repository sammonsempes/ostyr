use std::collections::BTreeMap;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceKind {
    Qemu,
    Lxc,
    Node,
    Storage,
}


/// Identity of a resource: the vmid for a guest, the node name for a node, `node/storage` for a storage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemKey {
    pub kind: ResourceKind,
    pub key: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub kind: ResourceKind,
    pub key: String,
    pub name: Option<String>,
    pub node: String,
    pub status: Option<String>,
    pub max_cpu: Option<u64>,
    pub max_mem: Option<u64>,
    pub max_disk: Option<u64>,
    pub template: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Unparsable,
    BadField,
    Duplicate,
    OtherType,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skipped {
    pub unparsable: usize,
    pub bad_field: usize,
    pub duplicate: usize,
    pub other_type: usize,
    pub key_lost: usize,
    pub refused_keys: Vec<ItemKey>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub items: Vec<Resource>,
    pub skipped: Skipped,
}


/// Privileges granted on one ACL path; the flag is the Proxmox propagate flag (1 or 0), a privilege listed with 0 is still held on that path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPrivileges {
    pub path: String,
    pub privileges: BTreeMap<String, u8>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    pub paths: Vec<PathPrivileges>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub kind: ResourceKind,
    pub key: String,
    pub name: Option<String>,
    pub node: String,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryDiff {
    pub created: Vec<ItemRef>,
    pub retired: Vec<ItemRef>,
    pub changed: Vec<ItemRef>,
    pub unreadable: Vec<ItemKey>,
    pub retired_unreadable: Vec<ItemKey>,
}
