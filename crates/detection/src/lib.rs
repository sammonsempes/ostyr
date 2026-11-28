//! Stream detection: events from NATS JetStream through the correlation engine into the alert store (spec section 4).

pub mod detect;
pub mod error;
pub mod id;
pub mod logging;
pub mod model;
pub mod pg;
pub mod retro;
pub mod retro_cursor;
pub mod retro_rules;
pub mod retro_step;
pub mod run;
#[cfg(unix)]
pub mod serve;
pub mod settings;
pub mod store;
pub mod types;
