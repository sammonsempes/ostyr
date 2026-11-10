//! Patch rollout ring gating (spec sections 21 and 10): which ring may proceed and which devices may install or reboot now.

pub mod commands;
pub mod decide;
pub mod error;
pub mod limits;
pub mod model;
pub mod policy;
pub mod types;
