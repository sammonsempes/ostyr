//! Batcher between the event bus and storage, with at-least-once acknowledgement (spec sections 4 and 12).

pub mod batcher;
pub mod clickhouse;
pub mod error;
pub mod model;
pub mod parse;
pub mod pipeline;
pub mod settings;
pub mod tenant;
pub mod types;
