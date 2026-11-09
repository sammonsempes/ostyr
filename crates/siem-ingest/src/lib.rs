//! Batcher between the event bus and storage, with at-least-once acknowledgement (spec sections 4 and 12).

pub mod batcher;
pub mod error;
pub mod model;
pub mod parse;
pub mod settings;
pub mod types;
