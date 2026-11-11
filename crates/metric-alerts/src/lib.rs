//! Metric alert rules (spec section 20): rule files and their pure evaluation over a series.

pub mod alerting;
pub mod error;
pub mod evaluate;
pub mod fetch;
pub mod fetch_cli;
pub mod fingerprint;
pub mod forecast;
pub mod model;
pub mod query;
pub mod round;
pub mod rules;
pub mod state;
pub mod token;
pub mod types;
pub mod windows;
