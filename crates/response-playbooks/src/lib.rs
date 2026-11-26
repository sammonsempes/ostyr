//! Playbook parsing, validation and simulation (spec section 10); nothing here executes an action.

pub mod api;
pub mod api_model;
pub mod backend;
pub mod batch;
pub mod bundle;
pub mod catalogue;
pub mod cli;
pub mod error;
pub mod expr;
pub mod feed;
pub mod model;
pub mod params;
pub mod render;
pub mod run;
pub mod runs;
pub mod runs_read;
pub mod serve;
pub mod service;
pub mod simulate;
pub mod trigger;
pub mod types;
pub mod validate;
pub mod walk;
