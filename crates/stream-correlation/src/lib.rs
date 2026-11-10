//! Sigma correlation rules over a stream of ECS events, with persistent windows (spec sections 4 and 19).

pub mod base;
pub mod check;
pub mod checkpoint;
pub mod cli;
pub mod condition;
pub mod correlation;
pub mod engine;
pub mod error;
pub mod field;
pub mod level;
pub mod reload;
pub mod ruleset;
pub mod selection;
pub mod types;
pub mod window;
