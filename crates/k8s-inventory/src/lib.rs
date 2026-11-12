//! Bounded inventory of Kubernetes pods and nodes from the API list JSON, and the diff between two inventories (spec section 22).

pub mod diff;
pub mod error;
pub mod inventory;
pub mod limits;
pub mod model;
pub mod parse;
pub mod text;
