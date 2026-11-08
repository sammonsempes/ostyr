//! gRPC channel between the endpoint agents and the management server over mutual TLS 1.3 (spec sections 4 and 12).


pub mod agent_app;
pub mod app;
pub mod client;
pub mod commands;
pub mod error;
pub mod identity;
pub mod limits;
pub mod model;
pub mod presence;
pub mod proto;
pub mod revocation;
pub mod server;
pub mod server_app;
pub mod services;
pub mod settings;
pub mod sink;
pub mod tls;
pub mod types;
