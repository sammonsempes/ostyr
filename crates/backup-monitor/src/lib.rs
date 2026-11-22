//! Restic and Borg snapshot listings: bounded parse, critical host coverage, deletion and retention findings (spec section 6).

#[cfg(unix)]
pub mod borg;
pub mod compare;
pub mod coverage;
pub mod declarations;
pub mod error;
pub mod model;
pub mod parse;
#[cfg(unix)]
pub mod report;
#[cfg(unix)]
pub mod restic;
pub mod text;
pub mod types;
