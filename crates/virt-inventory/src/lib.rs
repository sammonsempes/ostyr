//! Bounded inventory of Proxmox VE resources from the management API answers, the read-only token check and the diff between two inventories (spec section 22).

pub mod diff;
pub mod error;
pub mod inventory;
pub mod limits;
pub mod model;
pub mod proxmox;
pub mod readonly;
