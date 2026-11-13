//! Network topology links from LLDP neighbour reports, with a last-seen time and a staleness rule (spec section 22).

pub mod error;
pub mod limits;
pub mod links;
pub mod lldp;
pub mod model;
pub mod text;
pub mod types;
