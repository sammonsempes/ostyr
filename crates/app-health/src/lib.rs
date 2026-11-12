//! NTP drift and systemd unit health from tool output, assessed against files of thresholds and expectations.

pub mod assess;
pub mod error;
pub mod grammar;
pub mod journal;
pub mod limits;
pub mod measures;
pub mod model;
pub mod parse;
pub mod thresholds;
pub mod units;
