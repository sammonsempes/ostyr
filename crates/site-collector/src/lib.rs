//! Site collector: admission and parsing of syslog messages from unauthenticated LAN peers (spec section 22).

pub mod admission;
pub mod error;
pub mod frame;
pub mod model;
pub mod parse;
pub mod process;
pub mod spool;
pub mod spool_model;
pub mod types;
