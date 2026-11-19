//! The only way the platform reaches a language model: bounded request, bounded answer, telemetry sent as tagged data.

pub mod budget;
pub mod chat;
pub mod error;
pub mod limits;
pub mod model;
pub mod pg;
pub mod request;
pub mod response;
pub mod settings;
pub mod transport;
pub mod types;
