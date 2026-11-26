//! Linux file integrity monitoring: a role table of watched files and honeytokens, rendered as a Tetragon TracingPolicy, and the mapping of its events.

pub mod classify;
pub mod cli;
pub mod content;
pub mod error;
pub mod limits;
pub mod model;
#[cfg(target_os = "linux")]
pub mod package;
#[cfg(target_os = "linux")]
pub mod plant;
pub mod policy;
pub mod roles;
pub mod types;


#[cfg(not(target_os = "linux"))]
pub use cli::plant;
