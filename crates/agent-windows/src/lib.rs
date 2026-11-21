//! Windows agent: reads the Sysmon and Security event logs through `wevtutil` into the agent channel spool.

pub mod cursor;
pub mod cut;
pub mod error;
pub mod item;
pub mod lines;
pub mod model;
pub mod newest;
pub mod poll;
pub mod run;
pub mod split;
pub mod stream;
pub mod system;
pub mod types;
pub mod utf16;
