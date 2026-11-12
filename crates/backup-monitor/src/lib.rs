//! Restic and Borg snapshot listings: bounded parse, critical host coverage, deletion and retention findings (spec section 6).

pub mod compare;
pub mod coverage;
pub mod declarations;
pub mod error;
pub mod model;
pub mod parse;
pub mod text;
pub mod types;
