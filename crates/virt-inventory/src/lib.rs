//! Bounded inventory of Proxmox VE resources from the management API answers, the read-only token check and the diff between two inventories (spec section 22).

pub mod cmdb_sync;
pub mod degraded;
pub mod diff;
pub mod error;
pub mod fetch;
pub mod hangup;
pub mod inventory;
pub mod limits;
pub mod model;
pub mod proxmox;
pub mod readonly;
pub mod serve;
pub mod service;
pub mod settings;
pub mod stop;
pub mod stop_bound;
#[cfg(unix)]
pub mod trusted;
pub mod types;
pub mod vsphere;
