//! Entity risk score from weighted, decaying detection points (spec section 7, "Risk score per entity"), and its read-only REST API.

pub mod api;
pub mod api_model;
pub mod backend;
pub mod cache;
pub mod error;
pub mod model;
pub mod score;
pub mod source;
pub mod types;
pub mod weights;
