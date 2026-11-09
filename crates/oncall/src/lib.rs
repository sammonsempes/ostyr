//! Pure on-call library (spec section 20), slice 1: schedule and escalation policy files, who is on call, which level is due.

pub mod error;
pub mod escalation;
pub mod grouping;
pub mod limits;
pub mod load;
pub mod model;
pub mod schedule;
pub mod silence;
pub mod validate;
