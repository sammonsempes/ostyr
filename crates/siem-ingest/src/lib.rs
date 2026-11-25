//! Batcher between the event bus and storage, with at-least-once acknowledgement (spec sections 4 and 12).

pub mod batcher;
pub mod clickhouse;
pub mod dead;
pub mod error;
pub mod logging;
pub mod model;
pub mod nats;
pub mod nats_settings;
pub mod parse;
pub mod pipeline;
pub mod reader_profile;
pub mod serve;
pub mod settings;
pub mod tenant;
pub mod types;
