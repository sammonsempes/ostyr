//! Parses one reported message into a triage record and its observables (spec section 9, T605).

pub mod auth;
pub mod claim;
pub mod error;
#[cfg(unix)]
pub mod isolate;
pub mod limits;
pub mod mime;
pub mod model;
pub mod observables;
pub mod policy;
pub mod region;
pub mod scan;
pub mod shapes;
pub mod text;
pub mod triage;
pub mod types;
pub mod urls;
