//! Single-event Sigma rules compiled to ClickHouse SQL over ECS events (spec sections 4 and 7).

pub mod cli;
pub mod compile;
pub mod condition;
pub mod error;
pub mod mapping;
pub mod modifier;
pub mod rule;
pub mod selection;
pub mod sql;
pub mod types;
pub mod value;
