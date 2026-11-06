//! gRPC channel between the endpoint agents and the management server over mutual TLS 1.3 (spec sections 4 and 12).


pub mod client;
pub mod error;
pub mod identity;
pub mod model;
pub mod proto;
pub mod server;
pub mod tls;
pub mod types;
