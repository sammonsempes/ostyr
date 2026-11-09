//! Script manifests with typed parameters and the argument vector of a launch (spec section 21).

pub mod argv;
#[cfg(unix)]
pub mod cgroup;
pub mod check;
pub mod digest;
pub mod error;
#[cfg(unix)]
pub mod launch;
pub mod load;
pub mod model;
pub mod params;
pub mod path;
pub mod pattern;
pub mod types;
