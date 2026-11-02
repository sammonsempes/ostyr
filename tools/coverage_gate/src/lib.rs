//! Per-file line and branch coverage gate over a `cargo llvm-cov --json` export.

pub mod check;
pub mod error;
pub mod export;
pub mod run;
pub mod scan;
