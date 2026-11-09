//! Pure on-call library (spec section 20), slice 1: schedule and escalation policy files, who is on call, which level is due.

pub mod channel;
pub mod error;
pub mod escalation;
pub mod grouping;
pub mod limits;
pub mod load;
pub mod model;
pub mod notify;
pub mod render;
pub mod schedule;
pub mod secret;
pub mod settings;
pub mod silence;
pub mod smtp;
pub mod transport;
pub mod types;
pub mod validate;
