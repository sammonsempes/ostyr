//! Bounded OTLP trace decoding into span rows with file-declared head sampling (spec section 20).

pub mod cli;
pub mod decode;
pub mod insert;
pub mod insert_cli;
pub mod model;
pub mod receive;
pub mod reload;
pub mod run;
pub mod sampling;
pub mod scan;
pub mod senders;
pub mod settings;
pub mod types;
