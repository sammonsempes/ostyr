//! NTP drift from `chronyc -c tracking` and `timedatectl show`, assessed against a threshold file.

pub mod assess;
pub mod error;
pub mod grammar;
pub mod limits;
pub mod measures;
pub mod model;
pub mod parse;
pub mod thresholds;
