//! Active Directory posture checks over a bounded JSON snapshot of directory entries (spec section 7).

pub mod checks;
pub mod error;
pub mod filetime;
pub mod limits;
pub mod model;
pub mod report;
pub mod snapshot;
pub mod thresholds;
