//! The one routine command allocator: sequences in PostgreSQL, signed envelopes staged for the gateway (unix only).
#![cfg(unix)]

pub mod error;
pub mod issue;
pub mod key;
pub mod limits;
pub mod queue;
pub mod sequence;
pub mod types;
