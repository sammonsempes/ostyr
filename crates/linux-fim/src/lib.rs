//! Linux file integrity monitoring: a role table of watched files and honeytokens, rendered as a Tetragon TracingPolicy, and the mapping of its events.

pub mod classify;
pub mod cli;
pub mod error;
pub mod limits;
pub mod model;
pub mod policy;
pub mod roles;
pub mod types;
