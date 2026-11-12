//! Bounded OTLP trace decoding into span rows with file-declared head sampling (spec section 20).

pub mod cli;
pub mod decode;
pub mod model;
pub mod sampling;
pub mod types;
