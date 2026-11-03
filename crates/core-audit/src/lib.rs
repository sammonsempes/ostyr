//! Append-only, hash-chained audit log shared by every module (spec sections 4, 12 and 16).

pub mod canonical;
pub mod cli;
pub mod ecs;
pub mod error;
pub mod log;
pub mod model;
pub mod redact;
pub mod types;
pub mod verify;
