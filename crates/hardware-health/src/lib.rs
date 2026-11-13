//! Typed health verdict and measures from the JSON of `smartctl --json=c -a`.

pub mod assess;
pub mod error;
pub mod grammar;
pub mod limits;
pub mod measures;
pub mod model;
pub mod parse;
pub mod ups;
pub mod ups_assess;
