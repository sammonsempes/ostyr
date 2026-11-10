//! Stream detection: events from NATS JetStream through the correlation engine into the alert store (spec section 4).

pub mod detect;
pub mod error;
pub mod id;
pub mod model;
pub mod run;
pub mod settings;
pub mod store;
pub mod types;
