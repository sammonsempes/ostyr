//! Bounded OTLP trace decoding into span rows with file-declared head sampling (spec section 20).

pub mod cli;
pub mod decode;
pub mod insert;
pub mod insert_cli;
pub mod model;
pub mod run;
pub mod sampling;
pub mod scan;
pub mod types;
