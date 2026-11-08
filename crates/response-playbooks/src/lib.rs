//! Playbook parsing, validation and simulation (spec section 10); nothing here executes an action.

pub mod bundle;
pub mod catalogue;
pub mod cli;
pub mod error;
pub mod expr;
pub mod model;
pub mod params;
pub mod render;
pub mod run;
pub mod simulate;
pub mod trigger;
pub mod types;
pub mod validate;
pub mod walk;
