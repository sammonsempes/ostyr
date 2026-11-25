//! Deterministic deduplication and grouping of alerts before any AI call, and its read-only REST route.

pub mod error;
pub mod group;
pub mod limits;
pub mod model;
pub mod route;
pub mod types;
pub mod view;
